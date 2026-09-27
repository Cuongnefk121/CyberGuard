const BACKEND =
    "https://cyberguard-jx83.onrender.com/scan?domain=";

const params =
    new URLSearchParams(
        window.location.search
    );

const originalUrl =
    params.get("url");

const status =
    document.getElementById("status");

const result =
    document.getElementById("result");

function getDomain(url)
{
    try
    {
        let domain =
            new URL(url).hostname;

        domain =
            domain.replace(
                /^www\./,
                ""
            );

        return domain;
    }
    catch (e)
    {
        return "";
    }
}

async function checkWebsite()
{
    if (!originalUrl)
    {
        status.innerText =
            "Không tìm thấy website.";
        return;
    }

    let domain =
        getDomain(originalUrl);

    if (!domain)
    {
        status.innerText =
            "Không thể xác định tên miền.";
        return;
    }

    status.innerText =
        "Đang kiểm tra " +
        domain +
        "...";

    try
    {
        let url =
            BACKEND +
            encodeURIComponent(domain);

        console.log(
            "CyberGuard request:",
            url
        );

        let response =
            await fetch(url);

        console.log(
            "HTTP:",
            response.status
        );

        if (!response.ok)
        {
            throw new Error(
                "HTTP " +
                response.status
            );
        }

        let data =
            await response.json();

        console.log(
            "CyberGuard response:",
            data
        );

        let malicious =
            Number(data.malicious);

        if (Number.isNaN(malicious))
        {
            throw new Error(
                "Invalid malicious value"
            );
        }

        if (malicious >= 3)
        {
            let warningUrl =
                chrome.runtime.getURL(
                    "warning.html"
                ) +
                "?url=" +
                encodeURIComponent(
                    originalUrl
                ) +
                "&domain=" +
                encodeURIComponent(
                    domain
                ) +
                "&malicious=" +
                malicious;

            window.location.href =
                warningUrl;

            return;
        }

        status.innerText =
            "Website chưa bị phát hiện nguy hiểm.";

        result.innerText =
            "VirusTotal phát hiện: " +
            malicious +
            " engine.";

        setTimeout(
            function()
            {
                window.location.href =
                    originalUrl;
            },
            500
        );
    }
    catch (error)
    {
        console.error(
            "CyberGuard ERROR:",
            error
        );

        status.innerText =
            "⚠️ Cannot connect to CyberGuard Backend.";

        result.innerText =
            error.message;
    }
}

checkWebsite();
