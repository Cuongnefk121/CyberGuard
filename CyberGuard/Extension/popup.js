document.getElementById(
    "scan"
).addEventListener(
    "click",
    async function()
    {
        let result =
            document.getElementById(
                "result"
            );


        result.innerText =
            "Scanning...";


        chrome.tabs.query(
            {
                active: true,

                currentWindow: true
            },


            async function(tabs)
            {
                if (
                    !tabs[0] ||
                    !tabs[0].url
                )
                {
                    result.innerText =
                        "Cannot get website.";

                    return;
                }


                try
                {
                    let site =
                        new URL(
                            tabs[0].url
                        );


                    let domain =
                        site.hostname;


                    let response =
                        await fetch(
                            "http://127.0.0.1:8080/scan?domain=" +
                            encodeURIComponent(
                                domain
                            )
                        );


                    let data =
                        await response.json();


                    if (data.error)
                    {
                        result.innerText =
                            data.error;

                        return;
                    }


                    if (
                        data.malicious >= 3
                    )
                    {
                        result.innerText =
                            "⚠️ DANGEROUS\n\n" +
                            "Malicious detections: " +
                            data.malicious;
                    }
                    else
                    {
                        result.innerText =
                            "🛡️ SAFE\n\n" +
                            "Malicious detections: " +
                            data.malicious;
                    }
                }
                catch (error)
                {
                    result.innerText =
                        "Cannot connect to CyberGuard Backend.";
                }
            }
        );
    }
);