const params =
    new URLSearchParams(
        window.location.search
    );


const originalUrl =
    params.get("url");


const domain =
    params.get("domain");


const malicious =
    params.get("malicious");


const domainElement =
    document.getElementById(
        "domain"
    );


const maliciousElement =
    document.getElementById(
        "malicious"
    );


const backButton =
    document.getElementById(
        "back"
    );


const continueButton =
    document.getElementById(
        "continue"
    );


if (domainElement)
{
    domainElement.innerText =
        domain || "Unknown";
}


if (maliciousElement)
{
    maliciousElement.innerText =
        malicious || "0";
}


/* =========================
   BACK
========================= */

if (backButton)
{
    backButton.addEventListener(
        "click",
        function()
        {
            window.history.back();
        }
    );
}


/* =========================
   CONTINUE
========================= */

if (continueButton)
{
    continueButton.addEventListener(
        "click",
        function()
        {
            if (!originalUrl)
                return;


            chrome.runtime.sendMessage(
                {
                    action:
                        "ALLOW_CURRENT_URL",

                    url:
                        originalUrl
                },
                function()
                {
                    window.location.href =
                        originalUrl;
                }
            );
        }
    );
}
