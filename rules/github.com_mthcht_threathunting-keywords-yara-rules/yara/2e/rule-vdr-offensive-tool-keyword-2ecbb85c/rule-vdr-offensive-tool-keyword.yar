rule rule_VDR_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VDR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VDR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VDR_offensive_tool_keyword = /\srwf\.py\s/ nocase ascii wide
                        $string2_VDR_offensive_tool_keyword = /\.\/rwf\.py/
                        $string3_VDR_offensive_tool_keyword = /\/VDR\.git/ nocase ascii wide
                        $string4_VDR_offensive_tool_keyword = /\/VDR\-main\.zip/ nocase ascii wide
                        $string5_VDR_offensive_tool_keyword = /\\VDR\-main\.zip/ nocase ascii wide
                        $string6_VDR_offensive_tool_keyword = "EoP PoC exploiting the AMD driver " nocase ascii wide
                        $string7_VDR_offensive_tool_keyword = "EoP PoC exploiting the Intel driver " nocase ascii wide
                        $string8_VDR_offensive_tool_keyword = /eop_pdfwkrnl\.py/ nocase ascii wide
                        $string9_VDR_offensive_tool_keyword = /eop_pdfwkrnl_loop\.py/ nocase ascii wide
                        $string10_VDR_offensive_tool_keyword = /eop_rtport\.py/ nocase ascii wide
                        $string11_VDR_offensive_tool_keyword = /eop_stdcdrvws64\.py/ nocase ascii wide
                        $string12_VDR_offensive_tool_keyword = /System\stoken\sis\scopied\sto\sthe\scurrent\sprocess\.\sExecuting\scmd\.exe\.\./ nocase ascii wide
                        $string13_VDR_offensive_tool_keyword = "TakahiroHaruyama/VDR" nocase ascii wide

    condition:
        any of them
}