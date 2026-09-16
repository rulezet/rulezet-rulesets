rule rule_ADCollector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADCollector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCollector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADCollector_offensive_tool_keyword = " --LocalGMEnum --Host " nocase ascii wide
                        $string2_ADCollector_offensive_tool_keyword = /\sADCollector\.exe/ nocase ascii wide
                        $string3_ADCollector_offensive_tool_keyword = " --SessionEnum --Host " nocase ascii wide
                        $string4_ADCollector_offensive_tool_keyword = " --UserEnum --Host " nocase ascii wide
                        $string5_ADCollector_offensive_tool_keyword = /\.exe\s\-\-ACLScan\s.{0,1000}\s\-\-OU\s/ nocase ascii wide
                        $string6_ADCollector_offensive_tool_keyword = /\.exe\s\-\-LDAPs\s\-\-DisableSigning/ nocase ascii wide
                        $string7_ADCollector_offensive_tool_keyword = /\/ADCollector\.exe/ nocase ascii wide
                        $string8_ADCollector_offensive_tool_keyword = /\/ADCollector\.git/ nocase ascii wide
                        $string9_ADCollector_offensive_tool_keyword = /\\ADCollector\.exe/ nocase ascii wide
                        $string10_ADCollector_offensive_tool_keyword = /\\ADCollector3\.sln/ nocase ascii wide
                        $string11_ADCollector_offensive_tool_keyword = /\\ADCollector3\\/ nocase ascii wide
                        $string12_ADCollector_offensive_tool_keyword = "16e9f3c3f2a4264e3be9d2ddfe8d4ad409f4db17c077efd372389fbfe89f727b" nocase ascii wide
                        $string13_ADCollector_offensive_tool_keyword = "558a73bf1f4a3ecc59133a10d1a7892712f2bd30326f86a12d5c7060274d734d" nocase ascii wide
                        $string14_ADCollector_offensive_tool_keyword = /ADCollector3\.csproj/ nocase ascii wide
                        $string15_ADCollector_offensive_tool_keyword = "D1AE1ACF-8AA2-4935-ACDF-EC22BAE2DF76" nocase ascii wide
                        $string16_ADCollector_offensive_tool_keyword = "dev-2null/ADCollector" nocase ascii wide

    condition:
        any of them
}