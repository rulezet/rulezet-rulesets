rule PackMyPayload
{
    meta:
        description = "Detection patterns for the tool 'PackMyPayload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PackMyPayload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --backdoor " nocase ascii wide
                        $string2 = /\/PackMyPayload\.git/ nocase ascii wide
                        $string3 = "/PackMyPayload/" nocase ascii wide
                        $string4 = /\[\+\]\sBackdoored\sexisting\s7zip\swith\sspecified\sinput\sfile/ nocase ascii wide
                        $string5 = /\[\+\]\sBackdoored\sexisting\sISO\s/ nocase ascii wide
                        $string6 = /\[\+\]\sBackdoored\sexisting\sMSI\s/ nocase ascii wide
                        $string7 = /\[\+\]\sBackdoored\sexisting\sVHD\s/ nocase ascii wide
                        $string8 = /Backdooring\sMSI\sfiles\sis\scurrently\snot\ssupported\./ nocase ascii wide
                        $string9 = "ddde81ecf809882929faefd5887095a9d8671979f0c4d68579fa8b3a07674768" nocase ascii wide
                        $string10 = "File specifed to backdoor does not exist: " nocase ascii wide
                        $string11 = "mgeeky/PackMyPayload" nocase ascii wide
                        $string12 = /PackMyPayload\.py/ nocase ascii wide
                        $string13 = "PackMyPayload-master" nocase ascii wide

    condition:
        any of them
}