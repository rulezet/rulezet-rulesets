rule VDR
{
    meta:
        description = "Detection patterns for the tool 'VDR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VDR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srwf\.py\s/ nocase ascii wide
                        $string2 = /\.\/rwf\.py/
                        $string3 = /\/VDR\.git/ nocase ascii wide
                        $string4 = /\/VDR\-main\.zip/ nocase ascii wide
                        $string5 = /\\VDR\-main\.zip/ nocase ascii wide
                        $string6 = "EoP PoC exploiting the AMD driver " nocase ascii wide
                        $string7 = "EoP PoC exploiting the Intel driver " nocase ascii wide
                        $string8 = /eop_pdfwkrnl\.py/ nocase ascii wide
                        $string9 = /eop_pdfwkrnl_loop\.py/ nocase ascii wide
                        $string10 = /eop_rtport\.py/ nocase ascii wide
                        $string11 = /eop_stdcdrvws64\.py/ nocase ascii wide
                        $string12 = /System\stoken\sis\scopied\sto\sthe\scurrent\sprocess\.\sExecuting\scmd\.exe\.\./ nocase ascii wide
                        $string13 = "TakahiroHaruyama/VDR" nocase ascii wide

    condition:
        any of them
}