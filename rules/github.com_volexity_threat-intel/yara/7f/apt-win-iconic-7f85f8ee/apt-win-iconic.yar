rule apt_win_iconic: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detect the ICONIC loader."
        hash1 = "f79c3b0adb6ec7bcc8bc9ae955a1571aaed6755a28c8b17b1d7595ee86840952"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $internal_name =  "samcli.dll"

        $str1 = "gzip, deflate, br"
        $str2 = "__tutma"
        $str3 = "__tutmc"
        $str4 = "ChainingModeGCM" wide
        $str5 = "ChainingMode" wide
        $str6 = "icon%d.ico" wide

    condition:
        all of them
}