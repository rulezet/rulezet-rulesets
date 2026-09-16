rule GlllPowerloader
{
    meta:
        description = "Detection patterns for the tool 'GlllPowerloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GlllPowerloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGlllPowerLoader\.py/ nocase ascii wide
                        $string2 = /\/APC_Injection\.cpp/ nocase ascii wide
                        $string3 = /\/GlllPowerloader\.git/ nocase ascii wide
                        $string4 = /\/GlllPowerLoader\.py/ nocase ascii wide
                        $string5 = /\[\+\]\s\\u57fa\\u4e8esyswhispers\\u7684shellcode\\u52a0\\u8f7d\\u5668/ nocase ascii wide
                        $string6 = /\[\+\]\s\\u68c0\\u6d4b\\u5230Stageless\spayload/ nocase ascii wide
                        $string7 = /\[\+\]\sGenerated\ssuccessfully\!\sa\.dll/ nocase ascii wide
                        $string8 = /\[\+\]\sGenerated\ssuccessfully\!\sa\.exe/ nocase ascii wide
                        $string9 = /\[IO\.File\]\:\:ReadAllText\(.{0,1000}stubps1tovbs\.ps1/ nocase ascii wide
                        $string10 = /\\APC_Injection\.cpp/ nocase ascii wide
                        $string11 = /\\GlllPowerLoader\.py/ nocase ascii wide
                        $string12 = /\\GlllPowerLoader\-master/ nocase ascii wide
                        $string13 = /\\Ps1ToVbs\.ps1/ nocase ascii wide
                        $string14 = /\\wwwwwwwwwwwwntdll\.dll/ nocase ascii wide
                        $string15 = "54d3497f0b4197a649280a6f464d71154d7ecbcc663ab00a3805e820900a7955" nocase ascii wide
                        $string16 = "5643f39d347a5b36f195edcd9dbba33cc3417d76ad99892a029aefa96817b41a" nocase ascii wide
                        $string17 = "67908b4e774d138792557c430f8ec4f48aa9094b0c639bd57e7f49aacc17788e" nocase ascii wide
                        $string18 = "88391b7725953b6c37aa40ce11c2f80894ed4216f3972bef9c5738cc1771b143" nocase ascii wide
                        $string19 = /del\sGreen\.vbs/ nocase ascii wide
                        $string20 = /del\sPs1ToVbs\.ps1\\"/ nocase ascii wide
                        $string21 = "e74146d0354389935edf4ef0dcfdf659572b1444db54f08cf0c7ade206fee3c5" nocase ascii wide
                        $string22 = "INotGreen/GlllPowerloader" nocase ascii wide
                        $string23 = "powershell_to_vbs,APC_Injection,RemoteThreadContext,RemoteThreadSuspended" nocase ascii wide
                        $string24 = /powershell_to_vbs\.ps1/ nocase ascii wide
                        $string25 = "Sleeping for 10 seconds to avoid in-memory AV scan" nocase ascii wide
                        $string26 = /\-\-upload\-file.{0,1000}transfer\.sh/ nocase ascii wide

    condition:
        any of them
}