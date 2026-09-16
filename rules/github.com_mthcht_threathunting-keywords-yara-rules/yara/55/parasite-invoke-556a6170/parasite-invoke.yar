rule Parasite_Invoke
{
    meta:
        description = "Detection patterns for the tool 'Parasite-Invoke' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Parasite-Invoke"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sParasite\sInvoke\.exe/ nocase ascii wide
                        $string2 = /\.\sNice\sassembly\s\:D\s\./ nocase ascii wide
                        $string3 = /\.exe\s\-\-path\sC\:\\\s\-r\s\-\-method\sVirtualAlloc/ nocase ascii wide
                        $string4 = /\/Parasite\sInvoke\.exe/ nocase ascii wide
                        $string5 = /\/Parasite\%20Invoke\.exe/ nocase ascii wide
                        $string6 = /\/Parasite\-Invoke\.git/ nocase ascii wide
                        $string7 = /\\Parasite\sInvoke\.csproj/ nocase ascii wide
                        $string8 = /\\Parasite\sInvoke\.exe/ nocase ascii wide
                        $string9 = /\\Parasite\sInvoke\.pdb/ nocase ascii wide
                        $string10 = /\\Parasite\sInvoke\.sln/ nocase ascii wide
                        $string11 = /\\Parasite\sInvoke\\/ nocase ascii wide
                        $string12 = /\\Parasite\-Invoke\-main/ nocase ascii wide
                        $string13 = "===PARASITE INVOKE" nocase ascii wide
                        $string14 = "7CEC7793-3E22-455B-9E88-94B8D1A8F78D" nocase ascii wide
                        $string15 = /https\:\/\/pastebin\.com\/9JyjcMAH/ nocase ascii wide
                        $string16 = /https\:\/\/pastebin\.com\/iBeTbXCw/ nocase ascii wide
                        $string17 = /Michael\sZhmaylo\s\(github\.com\// nocase ascii wide
                        $string18 = "MzHmO/Parasite-Invoke" nocase ascii wide
                        $string19 = /Parasite\sInvoke_\.\-\'/ nocase ascii wide

    condition:
        any of them
}