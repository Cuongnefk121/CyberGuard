const params =
    new URLSearchParams(
        window.location.search
    );


const domain =
    params.get("domain");


const malicious =
    params.get("malicious");


const originalURL =
    params.get("url");


/*
    Hiển thị domain
*/

document.getElementById(
    "domain"
).innerText =
    domain || "Unknown";


/*
    Hiển thị số malicious
*/

document.getElementById(
    "count"
).innerText =
    "Malicious detections: " +
    (malicious || "Unknown");


/*
    =========================
    GO BACK
    =========================
*/

document.getElementById(
    "back"
).addEventListener(
    "click",
    function()
    {
        history.back();
    }
);


/*
    =========================
    CONTINUE
    =========================
*/

document.getElementById(
    "continue"
).addEventListener(
    "click",
    function()
    {
        if (!originalURL)
        {
            history.back();

            return;
        }


        /*
            Chỉ cho phép URL này
            trong tab hiện tại đi qua 1 lần.
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
                    lưu quyền bypass,
                    mới mở website.
                */

                window.location.replace(
                    originalURL
                );
            }
        );
    }
);