rule rule_PackMyPayload_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PackMyPayload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PackMyPayload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PackMyPayload_offensive_tool_keyword = " --backdoor " nocase ascii wide
                        $string2_PackMyPayload_offensive_tool_keyword = /\/PackMyPayload\.git/ nocase ascii wide
                        $string3_PackMyPayload_offensive_tool_keyword = "/PackMyPayload/" nocase ascii wide
                        $string4_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\s7zip\swith\sspecified\sinput\sfile/ nocase ascii wide
                        $string5_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sISO\s/ nocase ascii wide
                        $string6_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sMSI\s/ nocase ascii wide
                        $string7_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sVHD\s/ nocase ascii wide
                        $string8_PackMyPayload_offensive_tool_keyword = /Backdooring\sMSI\sfiles\sis\scurrently\snot\ssupported\./ nocase ascii wide
                        $string9_PackMyPayload_offensive_tool_keyword = "ddde81ecf809882929faefd5887095a9d8671979f0c4d68579fa8b3a07674768" nocase ascii wide
                        $string10_PackMyPayload_offensive_tool_keyword = "File specifed to backdoor does not exist: " nocase ascii wide
                        $string11_PackMyPayload_offensive_tool_keyword = "mgeeky/PackMyPayload" nocase ascii wide
                        $string12_PackMyPayload_offensive_tool_keyword = /PackMyPayload\.py/ nocase ascii wide
                        $string13_PackMyPayload_offensive_tool_keyword = "PackMyPayload-master" nocase ascii wide

    condition:
        any of them
}