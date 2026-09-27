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
        if (status)
        {
            status.innerText =
                "Không tìm thấy website.";
        }

        return;
    }


    let domain =
        getDomain(originalUrl);


    if (!domain)
    {
        if (status)
        {
            status.innerText =
                "Không thể xác định tên miền.";
        }

        return;
    }


    if (status)
    {
        status.innerText =
            "Đang kiểm tra " +
            domain +
            "...";
    }


    try
    {
        let response =
            await fetch(
                BACKEND +
                encodeURIComponent(
                    domain
                )
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
            Number(
                data.malicious
            );


        if (Number.isNaN(malicious))
        {
            throw new Error(
                "Kết quả không hợp lệ"
            );
        }


        console.log(
            "CyberGuard:",
            domain,
            "malicious =",
            malicious
        );


        /*
         * Website nguy hiểm
         */
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


        /*
         * Website an toàn
         */
        if (status)
        {
            status.innerText =
                "Website chưa bị phát hiện nguy hiểm.";
        }


        if (result)
        {
            result.innerText =
                "VirusTotal phát hiện: " +
                malicious +
                " engine.";
        }


        /*
         * Đợi 1.5 giây để hiển thị kết quả
         */
        setTimeout(
            function()
            {
                /*
                 * Báo cho background.js:
                 * URL này đã được kiểm tra,
                 * cho phép truy cập lần này.
                 */
                chrome.runtime.sendMessage(
                    {
                        action:
                            "ALLOW_CURRENT_URL",

                        url:
                            originalUrl
                    },
                    function()
                    {
                        /*
                         * Sau khi background.js
                         * nhận được lệnh bypass,
                         * quay lại website.
                         */
                        window.location.replace(
                            originalUrl
                        );
                    }
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


        if (status)
        {
            status.innerText =
                "⚠️ Cannot connect to CyberGuard Backend.";
        }


        if (result)
        {
            result.innerText =
                error.message;
        }
    }
}


checkWebsite();
