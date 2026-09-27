const BACKEND =
    "http://127.0.0.1:8080/scan?domain=";


/*
    Lưu URL được phép đi qua theo từng tab
*/
let bypassTabs = {};


/*
    Kiểm tra có phải website HTTP/HTTPS không
*/
function isWebsite(url)
{
    if (!url)
        return false;

    if (
        url.startsWith("chrome://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge-extension://") ||
        url.startsWith("file://")
    )
    {
        return false;
    }

    return (
        url.startsWith("http://") ||
        url.startsWith("https://")
    );
}


/*
    Khi website bắt đầu navigation
*/
chrome.webNavigation.onBeforeNavigate.addListener(
    function(details)
    {
        if (details.frameId !== 0)
            return;

        let url =
            details.url;

        if (!isWebsite(url))
            return;


        let tabId =
            details.tabId;


        /*
            Kiểm tra URL này có vừa được
            người dùng cho phép hay không
        */

        if (
            bypassTabs[tabId] &&
            bypassTabs[tabId] === url
        )
        {
            /*
                Chỉ bỏ qua đúng 1 lần
            */

            delete bypassTabs[tabId];

            console.log(
                "[CyberGuard] Allowed:",
                url
            );

            return;
        }


        /*
            Đưa sang trang kiểm tra
        */

        let checker =
            chrome.runtime.getURL(
                "check.html"
            );


        checker +=
            "?url=" +
            encodeURIComponent(url);


        console.log(
            "[CyberGuard] Checking:",
            url
        );


        chrome.tabs.update(
            tabId,
            {
                url: checker
            }
        );
    }
);


/*
    check.js gọi khi kiểm tra xong
*/
chrome.runtime.onMessage.addListener(
    function(message, sender, sendResponse)
    {
        if (!message)
            return;


        /*
            Kiểm tra đã hoàn thành
        */

        if (
            message.type ===
            "CHECK_FINISHED"
        )
        {
            console.log(
                "[CyberGuard] Check finished."
            );

            sendResponse({
                ok: true
            });

            return;
        }


        /*
            Cho phép một URL cụ thể
            trong một tab cụ thể
        */

        if (
            message.type ===
            "ALLOW_CURRENT_URL"
        )
        {
            if (!sender.tab)
            {
                sendResponse({
                    ok: false
                });

                return;
            }


            let tabId =
                sender.tab.id;


            let url =
                message.url;


            if (!url)
            {
                sendResponse({
                    ok: false
                });

                return;
            }


            bypassTabs[tabId] =
                url;


            console.log(
                "[CyberGuard] One-time bypass:",
                url
            );


            sendResponse({
                ok: true
            });
        }
    }
);


/*
    Xóa dữ liệu khi tab đóng
*/

chrome.tabs.onRemoved.addListener(
    function(tabId)
    {
        delete bypassTabs[tabId];
    }
);