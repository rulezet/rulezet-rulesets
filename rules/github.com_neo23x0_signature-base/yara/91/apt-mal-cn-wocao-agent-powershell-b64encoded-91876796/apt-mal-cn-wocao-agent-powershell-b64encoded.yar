rule APT_MAL_CN_Wocao_agent_powershell_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from Agent CSharp version"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "14e1702d-6229-5989-8bb7-cc9c0c321676"
    strings:
        $header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"

    condition:
        all of them
}