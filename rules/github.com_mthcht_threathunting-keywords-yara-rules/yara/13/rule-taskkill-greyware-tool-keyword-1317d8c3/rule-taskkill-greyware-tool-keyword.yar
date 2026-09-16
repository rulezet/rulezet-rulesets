rule rule_taskkill_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'taskkill' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "taskkill"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_taskkill_greyware_tool_keyword = "TASKKILL /F /FI \"PID ge 1000\" /FI \"WINDOWTITLE ne untitled" nocase ascii wide
                        $string2_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sALMon\.exe/ nocase ascii wide
                        $string3_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sALMon\.exe/ nocase ascii wide
                        $string4_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sALsvc\.exe/ nocase ascii wide
                        $string5_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sALsvc\.exe/ nocase ascii wide
                        $string6_taskkill_greyware_tool_keyword = /taskkill\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
                        $string7_taskkill_greyware_tool_keyword = /taskkill\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide
                        $string8_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sspa\.exe/ nocase ascii wide
                        $string9_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sspa\.exe/ nocase ascii wide
                        $string10_taskkill_greyware_tool_keyword = "taskkill /f /im sql" nocase ascii wide
                        $string11_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sswi_fc\.exe/ nocase ascii wide
                        $string12_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sswi_fc\.exe/ nocase ascii wide
                        $string13_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sswi_filter\.exe/ nocase ascii wide
                        $string14_taskkill_greyware_tool_keyword = /taskkill\s\/f\s\/im\sswi_filter\.exe/ nocase ascii wide
                        $string15_taskkill_greyware_tool_keyword = /taskkill\s\/im\sagntsvc\.exe\s\/F/ nocase ascii wide
                        $string16_taskkill_greyware_tool_keyword = /taskkill\s\/IM\sCNTAoSMgr\.exe\s\/F/ nocase ascii wide
                        $string17_taskkill_greyware_tool_keyword = /taskkill\s\/im\sdbeng50\.exe\s\/F/ nocase ascii wide
                        $string18_taskkill_greyware_tool_keyword = /taskkill\s\/im\sdbsnmp\.exe\s\/F/ nocase ascii wide
                        $string19_taskkill_greyware_tool_keyword = /taskkill\s\/im\sencsvc\.exe\s\/F/ nocase ascii wide
                        $string20_taskkill_greyware_tool_keyword = /taskkill\s\/im\sexcel\.exe\s\/F/ nocase ascii wide
                        $string21_taskkill_greyware_tool_keyword = /taskkill\s\/im\sfirefoxconfig\.exe\s\/F/ nocase ascii wide
                        $string22_taskkill_greyware_tool_keyword = /taskkill\s\/im\sinfopath\.exe\s\/F/ nocase ascii wide
                        $string23_taskkill_greyware_tool_keyword = /taskkill\s\/im\sisqlplussvc\.exe\s\/F/ nocase ascii wide
                        $string24_taskkill_greyware_tool_keyword = /taskkill\s\/IM\smbamtray\.exe\s\/F/ nocase ascii wide
                        $string25_taskkill_greyware_tool_keyword = /taskkill\s\/im\smsaccess\.exe\s\/F/ nocase ascii wide
                        $string26_taskkill_greyware_tool_keyword = /taskkill\s\/im\smsftesql\.exe\s\/F/ nocase ascii wide
                        $string27_taskkill_greyware_tool_keyword = /taskkill\s\/im\smspub\.exe\s\/F/ nocase ascii wide
                        $string28_taskkill_greyware_tool_keyword = /taskkill\s\/im\smydesktopqos\.exe\s\/F/ nocase ascii wide
                        $string29_taskkill_greyware_tool_keyword = /taskkill\s\/im\smydesktopservice\.exe\s\/F/ nocase ascii wide
                        $string30_taskkill_greyware_tool_keyword = /taskkill\s\/im\smysqld\.exe\s\/F/ nocase ascii wide
                        $string31_taskkill_greyware_tool_keyword = /taskkill\s\/im\smysqld\-nt\.exe\s\/F/ nocase ascii wide
                        $string32_taskkill_greyware_tool_keyword = /taskkill\s\/im\smysqld\-opt\.exe\s\/F/ nocase ascii wide
                        $string33_taskkill_greyware_tool_keyword = "taskkill /IM Ntrtsc" nocase ascii wide
                        $string34_taskkill_greyware_tool_keyword = /taskkill\s\/im\socautoupds\.exe\s\/F/ nocase ascii wide
                        $string35_taskkill_greyware_tool_keyword = /taskkill\s\/im\socomm\.exe\s\/F/ nocase ascii wide
                        $string36_taskkill_greyware_tool_keyword = /taskkill\s\/im\socssd\.exe\s\/F/ nocase ascii wide
                        $string37_taskkill_greyware_tool_keyword = /taskkill\s\/im\sonenote\.exe\s\/F/ nocase ascii wide
                        $string38_taskkill_greyware_tool_keyword = /taskkill\s\/im\soracle\.exe\s\/F/ nocase ascii wide
                        $string39_taskkill_greyware_tool_keyword = /taskkill\s\/im\soutlook\.exe\s\/F/ nocase ascii wide
                        $string40_taskkill_greyware_tool_keyword = /taskkill\s\/IM\sPccNTMon\.exe\s\/F/ nocase ascii wide
                        $string41_taskkill_greyware_tool_keyword = /taskkill\s\/im\spowerpnt\.exe\s\/F/ nocase ascii wide
                        $string42_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssavfmsesp\.exe\s\/f/ nocase ascii wide
                        $string43_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssqbcoreservice\.exe\s\/F/ nocase ascii wide
                        $string44_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssqlagent\.exe\s\/F/ nocase ascii wide
                        $string45_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssqlbrowser\.exe\s\/F/ nocase ascii wide
                        $string46_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssqlservr\.exe\s\/F/ nocase ascii wide
                        $string47_taskkill_greyware_tool_keyword = /taskkill\s\/im\ssynctime\.exe\s\/F/ nocase ascii wide
                        $string48_taskkill_greyware_tool_keyword = /taskkill\s\/im\stbirdconfig\.exe\s\/F/ nocase ascii wide
                        $string49_taskkill_greyware_tool_keyword = /taskkill\s\/im\sthebat\.exe\s\/F/ nocase ascii wide
                        $string50_taskkill_greyware_tool_keyword = /taskkill\s\/im\sthebat64\.exe\s\/F/ nocase ascii wide
                        $string51_taskkill_greyware_tool_keyword = /taskkill\s\/im\sthunderbird\.exe\s\/F/ nocase ascii wide
                        $string52_taskkill_greyware_tool_keyword = /taskkill\s\/IM\stmlisten\.exe\s\/F/ nocase ascii wide
                        $string53_taskkill_greyware_tool_keyword = /taskkill\s\/im\svisio\.exe\s\/F/ nocase ascii wide
                        $string54_taskkill_greyware_tool_keyword = /taskkill\s\/im\swinword\.exe\s\/F/ nocase ascii wide
                        $string55_taskkill_greyware_tool_keyword = /taskkill\s\/im\swordpad\.exe\s\/F/ nocase ascii wide
                        $string56_taskkill_greyware_tool_keyword = /taskkill\s\/im\sxfssvccon\.exe\s\/F/ nocase ascii wide
                        $string57_taskkill_greyware_tool_keyword = /taskkill\s\/im\szoolz\.exe\s\/F/ nocase ascii wide
                        $string58_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sfdhost\.exe/ nocase ascii wide
                        $string59_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sfdlauncher\.exe/ nocase ascii wide
                        $string60_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sfdlauncher\.exe/ nocase ascii wide
                        $string61_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sMsDtsSrvr\.exe/ nocase ascii wide
                        $string62_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\smsftesql\.exe/ nocase ascii wide
                        $string63_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\smsmdsrv\.exe/ nocase ascii wide
                        $string64_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\spg_ctl\.exe/ nocase ascii wide
                        $string65_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\spostgres\.exe/ nocase ascii wide
                        $string66_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sReportingServicesService\.exe/ nocase ascii wide
                        $string67_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sSQLAGENT\.EXE/ nocase ascii wide
                        $string68_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\ssqlbrowser\.exe/ nocase ascii wide
                        $string69_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\ssqlceip\.exe/ nocase ascii wide
                        $string70_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\ssqlservr\.exe/ nocase ascii wide
                        $string71_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\ssqlservr\.exe/ nocase ascii wide
                        $string72_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\ssqlwriter\.exe/ nocase ascii wide
                        $string73_taskkill_greyware_tool_keyword = /taskkill\s\-f\s\-im\sSsms\.exe/ nocase ascii wide
                        $string74_taskkill_greyware_tool_keyword = /taskkill\.exe\s\/F\s\/IM\slsass\.exe/ nocase ascii wide
                        $string75_taskkill_greyware_tool_keyword = /taskkill\.exe\s\/F\s\/IM\smsiexec\.exe/ nocase ascii wide
                        $string76_taskkill_greyware_tool_keyword = "tasklist /v /fi \"username eq system\"" nocase ascii wide
                        $string77_taskkill_greyware_tool_keyword = /tasklist\.exe\\"\s\/v\s\/fi\s\\"username\seq\ssystem\\"/ nocase ascii wide

    condition:
        any of them
}