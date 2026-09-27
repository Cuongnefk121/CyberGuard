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
        return new URL(url).hostname;
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
            Number(
                data.malicious
            );


        if (
            Number.isNaN(
                malicious
            )
        )
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
         * >= 3:
         * Hiển thị cảnh báo
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


            window.location.href =
                warningUrl;

            return;
        }


        /*
         * Website an toàn /
         * chưa đủ mức cảnh báo
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
            "CyberGuard error:",
            error
        );


        if (status)
        {
            status.innerText =
                "Không thể kết nối CyberGuard.";
        }


        if (result)
        {
            result.innerText =
                "Backend có thể đang khởi động. Vui lòng thử lại.";
        }
    }
}


checkWebsite();
