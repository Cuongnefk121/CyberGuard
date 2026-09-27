let bypassTabs = {};

chrome.webNavigation.onBeforeNavigate.addListener(
    function(details)
    {
        if (details.frameId !== 0)
            return;

        let url = details.url;

        if (
            url.startsWith("chrome://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("edge://") ||
            url.startsWith("about:")
        )
        {
            return;
        }

        if (bypassTabs[details.tabId] === url)
        {
            delete bypassTabs[details.tabId];
            return;
        }

        let checkUrl =
            chrome.runtime.getURL(
                "check.html"
            ) +
            "?url=" +
            encodeURIComponent(url);

        chrome.tabs.update(
            details.tabId,
            {
                url: checkUrl
            }
        );
    }
);


chrome.runtime.onMessage.addListener(
    function(message, sender, sendResponse)
    {
        if (
            message.action ===
            "ALLOW_CURRENT_URL"
        )
        {
            let tabId =
                sender.tab
                    ? sender.tab.id
                    : message.tabId;

            if (tabId !== undefined)
            {
                bypassTabs[tabId] =
                    message.url;
            }

            sendResponse({
                success: true
            });
        }

        return true;
    }
);


chrome.tabs.onRemoved.addListener(
    function(tabId)
    {
        delete bypassTabs[tabId];
    }
);
