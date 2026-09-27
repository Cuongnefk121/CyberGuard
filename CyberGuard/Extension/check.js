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
        let response =
            await fetch(
                BACKEND +
                encodeURIComponent(domain)
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

        let malicious =
            Number(data.malicious);

        if (Number.isNaN(malicious))
        {
            throw new Error(
                "Kết quả không hợp lệ"
            );
        }

        console.log(
            "CyberGuard:",
            domain,
            malicious
        );

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

            window.location.replace(
                warningUrl
            );

            return;
        }

        status.innerText =
            "Website chưa bị phát hiện nguy hiểm.";

        result.innerText =
            "VirusTotal phát hiện: " +
            malicious +
            " engine.";

        /*
         * Chờ một chút để người dùng
         * nhìn thấy kết quả rồi quay lại
         * website ban đầu.
         */
        setTimeout(
            function()
            {
                window.location.replace(
                    originalUrl
                );
            },
            1500
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
