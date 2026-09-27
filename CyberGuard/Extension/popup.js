const BACKEND =
    "https://cyberguard-jx83.onrender.com/scan?domain=";


const input =
    document.getElementById("domain");


const button =
    document.getElementById("check");


const result =
    document.getElementById("result");


if (button)
{
    button.addEventListener(
        "click",
        async function()
        {
            let domain =
                input.value.trim();


            if (!domain)
            {
                if (result)
                {
                    result.innerText =
                        "Vui lòng nhập tên miền.";
                }

                return;
            }


            domain =
                domain
                    .replace(
                        "https://",
                        ""
                    )
                    .replace(
                        "http://",
                        ""
                    )
                    .split("/")[0];


            if (result)
            {
                result.innerText =
                    "Đang kiểm tra...";
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


                if (
                    malicious >= 3
                )
                {
                    if (result)
                    {
                        result.innerText =
                            "⚠️ Cảnh báo: " +
                            malicious +
                            " engine phát hiện nguy hiểm.";
                    }
                }
                else
                {
                    if (result)
                    {
                        result.innerText =
                            "✅ Chưa phát hiện nguy hiểm. " +
                            malicious +
                            " engine.";
                    }
                }
            }
            catch (error)
            {
                console.error(
                    error
                );

                if (result)
                {
                    result.innerText =
                        "❌ Không thể kết nối backend.";
                }
            }
        }
    );
}
