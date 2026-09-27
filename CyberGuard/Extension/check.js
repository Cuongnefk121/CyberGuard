const params =
    new URLSearchParams(
        window.location.search
    );


const originalURL =
    params.get("url");


const status =
    document.getElementById(
        "status"
    );


const domainBox =
    document.getElementById(
        "domain"
    );


const BACKEND =
    "http://127.0.0.1:8080/scan?domain=";


/*
    Kiểm tra URL
*/

if (!originalURL)
{
    status.innerText =
        "Cannot determine website.";
}
else
{
    checkWebsite();
}


/*
    Hàm kiểm tra website
*/

async function checkWebsite()
{
    try
    {
        let site =
            new URL(
                originalURL
            );


        let domain =
            site.hostname;


        domainBox.innerText =
            domain;


        status.innerText =
            "🔎 Checking with CyberGuard...";


        console.log(
            "[CyberGuard] Checking:",
            domain
        );


        /*
            Gửi domain cho C++ Backend
        */

        let response =
            await fetch(
                BACKEND +
                encodeURIComponent(domain)
            );


        if (!response.ok)
        {
            status.innerText =
                "⚠️ CyberGuard Backend unavailable.";

            return;
        }


        let data =
            await response.json();


        /*
            Backend báo lỗi
        */

        if (data.error)
        {
            status.innerText =
                "⚠️ " +
                data.error;

            return;
        }


        let malicious =
            Number(
                data.malicious
            );


        console.log(
            "[CyberGuard]",
            domain,
            "malicious =",
            malicious
        );


        /*
            =========================
            WEBSITE NGUY HIỂM
            =========================
        */

        if (malicious >= 3)
        {
            let warning =
                chrome.runtime.getURL(
                    "warning.html"
                );


            warning +=
                "?domain=" +
                encodeURIComponent(
                    domain
                );


            warning +=
                "&malicious=" +
                encodeURIComponent(
                    malicious
                );


            warning +=
                "&url=" +
                encodeURIComponent(
                    originalURL
                );


            window.location.replace(
                warning
            );


            return;
        }


        /*
            =========================
            WEBSITE AN TOÀN
            =========================
        */

        status.innerText =
            "🛡️ Website appears safe.";


        /*
            Cho phép URL hiện tại
            đi qua đúng một lần
        */

        chrome.runtime.sendMessage(
            {
                type:
                    "ALLOW_CURRENT_URL",

                url:
                    originalURL
            },
            function()
            {
                /*
                    Sau khi background
                    nhận được quyền bypass
                    mới chuyển tới website.
                */

                window.location.replace(
                    originalURL
                );
            }
        );
    }
    catch (error)
    {
        console.log(
            "[CyberGuard] Error:",
            error
        );


        status.innerText =
            "⚠️ Cannot connect to CyberGuard Backend.";
    }
}