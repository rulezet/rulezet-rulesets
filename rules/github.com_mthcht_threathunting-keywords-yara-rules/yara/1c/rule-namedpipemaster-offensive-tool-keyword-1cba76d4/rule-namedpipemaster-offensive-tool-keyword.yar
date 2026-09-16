rule rule_NamedPipeMaster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NamedPipeMaster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NamedPipeMaster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NamedPipeMaster_offensive_tool_keyword = /\/NamedPipeMaster\.git/ nocase ascii wide
                        $string2_NamedPipeMaster_offensive_tool_keyword = "/NamedPipeMaster/tarball/" nocase ascii wide
                        $string3_NamedPipeMaster_offensive_tool_keyword = "/NamedPipeMaster/zipball/" nocase ascii wide
                        $string4_NamedPipeMaster_offensive_tool_keyword = "/NamedPipeMasterBase/" nocase ascii wide
                        $string5_NamedPipeMaster_offensive_tool_keyword = /\\\\Device\\\\NamedPipe\\\\NamedPipeMaster/ nocase ascii wide
                        $string6_NamedPipeMaster_offensive_tool_keyword = /\\Device\\NamedPipe\\NamedPipeMaster/ nocase ascii wide
                        $string7_NamedPipeMaster_offensive_tool_keyword = /\\NamedPipeEventDatabase\.cpp/ nocase ascii wide
                        $string8_NamedPipeMaster_offensive_tool_keyword = /\\NamedPipeMaster\.sln/ nocase ascii wide
                        $string9_NamedPipeMaster_offensive_tool_keyword = /\\NamedPipeMasterBase\\/ nocase ascii wide
                        $string10_NamedPipeMaster_offensive_tool_keyword = /\\NamedPipeMaster\-main/ nocase ascii wide
                        $string11_NamedPipeMaster_offensive_tool_keyword = "089e1f51fe8751dfbbc11c8ffd8d7b6121ac025d8e0c0c2f082e3d976d6af948" nocase ascii wide
                        $string12_NamedPipeMaster_offensive_tool_keyword = "195cbf85cbf9fc7dcd011b2658819cf3350195f61021cb7c5a6f6e32cba15f03" nocase ascii wide
                        $string13_NamedPipeMaster_offensive_tool_keyword = "2787cc9e36cc2aebada79515e19ca4daf36887a091ec8f41af187c96df4147af" nocase ascii wide
                        $string14_NamedPipeMaster_offensive_tool_keyword = "40ab3cf285a8ee70b183bd6f12c2b2fa0890df82ed38ce7833263781cbf37a19" nocase ascii wide
                        $string15_NamedPipeMaster_offensive_tool_keyword = "585e550d0435ab335e6c7fdfb7a609b7b8ead766fc3ee7ef1f93113b1d51e5d3" nocase ascii wide
                        $string16_NamedPipeMaster_offensive_tool_keyword = "5C87B2E6-8D24-4F1D-AB85-FC659F452AD0" nocase ascii wide
                        $string17_NamedPipeMaster_offensive_tool_keyword = "733a16c2eb4095398eab1a92ca5cea56a935f3df05a100fec3a1decda26d1e3f" nocase ascii wide
                        $string18_NamedPipeMaster_offensive_tool_keyword = "80bba5f788f3f4a7fa0e3a516fdd0dcd7eb1553065ee224090f18dec032a04cd" nocase ascii wide
                        $string19_NamedPipeMaster_offensive_tool_keyword = "8a15e1d1589aeac183ce00830f32e9399f88f1db811f00e537a5fac1ac8002a0" nocase ascii wide
                        $string20_NamedPipeMaster_offensive_tool_keyword = "95dcf74d21d688a7f2b887af56aeeae19c0d788ed863746f1edf19539a67ad37" nocase ascii wide
                        $string21_NamedPipeMaster_offensive_tool_keyword = "a0b87b7223b946059d61f7c955981ad9715a243f4b4116dd2dcb4352f9a02460" nocase ascii wide
                        $string22_NamedPipeMaster_offensive_tool_keyword = "act as a named pipe server to be connected by other clients" nocase ascii wide
                        $string23_NamedPipeMaster_offensive_tool_keyword = "C2F24BBD-4807-49F5-B5E2-77FF0E8B756B" nocase ascii wide
                        $string24_NamedPipeMaster_offensive_tool_keyword = "caa3f53715c68033d72a623dfcc2412cc86bce077d6081685ead3b1498e8b804" nocase ascii wide
                        $string25_NamedPipeMaster_offensive_tool_keyword = "d6edddd2dcac14dfe70c6b396236d6d3a95b0c1f6fe8fec38381049f3823bdb6" nocase ascii wide
                        $string26_NamedPipeMaster_offensive_tool_keyword = "E7BFFEE1-07C1-452C-8AF8-6AD30B1844FF" nocase ascii wide
                        $string27_NamedPipeMaster_offensive_tool_keyword = "e95eb9af49be9d5c4c95a832bd36c192a570f0dd649cfd24b81de5e3e6262236" nocase ascii wide
                        $string28_NamedPipeMaster_offensive_tool_keyword = "ea552615337ba9becf9c1341f4ad2556b204dca25982c123b2cfd6e218192b49" nocase ascii wide
                        $string29_NamedPipeMaster_offensive_tool_keyword = "f9e0d5910c1883ad6c902d895ebd813018ad7e5a0b4f5988d0c2ed861e9e08de" nocase ascii wide
                        $string30_NamedPipeMaster_offensive_tool_keyword = /Information\sCollection\svia\sDLL\sInjection\s\(Ring3\sHook\)/ nocase ascii wide
                        $string31_NamedPipeMaster_offensive_tool_keyword = /inject\s.{0,1000}\.dll\sinto\sa\sprocess\sas\sa\sproxy\sto\sinteract\swith\sthe\starget\snamed\spipe\sserver/ nocase ascii wide
                        $string32_NamedPipeMaster_offensive_tool_keyword = /Inject\sinto\sthe\sproxy\sprocess\sand\slet\sit\sopen\sa\snamed\spipe\sserver\./ nocase ascii wide
                        $string33_NamedPipeMaster_offensive_tool_keyword = "keep monitoring named pipe activities until enter is pressed" nocase ascii wide
                        $string34_NamedPipeMaster_offensive_tool_keyword = "NamedPipeMaster/releases/download/" nocase ascii wide
                        $string35_NamedPipeMaster_offensive_tool_keyword = /NamedPipeMaster\-32bit\.zip/ nocase ascii wide
                        $string36_NamedPipeMaster_offensive_tool_keyword = /NamedPipeMaster\-32bit\\/ nocase ascii wide
                        $string37_NamedPipeMaster_offensive_tool_keyword = /NamedPipeMaster\-64bit\.zip/ nocase ascii wide
                        $string38_NamedPipeMaster_offensive_tool_keyword = /NamedPipeMaster\-64bit\\/ nocase ascii wide
                        $string39_NamedPipeMaster_offensive_tool_keyword = "NamedPipeMasterLogger" nocase ascii wide
                        $string40_NamedPipeMaster_offensive_tool_keyword = /NamedPipeMaster\-main\.zip/ nocase ascii wide
                        $string41_NamedPipeMaster_offensive_tool_keyword = /NamedPipePoker\.cpp/ nocase ascii wide
                        $string42_NamedPipeMaster_offensive_tool_keyword = /NamedPipePoker\.h/ nocase ascii wide
                        $string43_NamedPipeMaster_offensive_tool_keyword = "NamedPipeProxyPoker" nocase ascii wide
                        $string44_NamedPipeMaster_offensive_tool_keyword = /Offensive\-Windows\-IPC\-1\-NamedPipes\./ nocase ascii wide
                        $string45_NamedPipeMaster_offensive_tool_keyword = /PeekNamedPipe\(fromPipe/ nocase ascii wide
                        $string46_NamedPipeMaster_offensive_tool_keyword = /\'PipeName\'\>\\NamedPipeMaster/ nocase ascii wide
                        $string47_NamedPipeMaster_offensive_tool_keyword = "RING0_ANONYMOUS_PIPE" nocase ascii wide
                        $string48_NamedPipeMaster_offensive_tool_keyword = "Ring0NamedPipeFilter " nocase ascii wide
                        $string49_NamedPipeMaster_offensive_tool_keyword = /Ring0NamedPipeFilter\.h/ nocase ascii wide
                        $string50_NamedPipeMaster_offensive_tool_keyword = /Ring3NamedPipeConsumer\.exe/ nocase ascii wide
                        $string51_NamedPipeMaster_offensive_tool_keyword = "Ring3NamedPipeMonitor" nocase ascii wide
                        $string52_NamedPipeMaster_offensive_tool_keyword = /Ring3NamedPipeMonitor\.dll/ nocase ascii wide
                        $string53_NamedPipeMaster_offensive_tool_keyword = "zeze-zeze/NamedPipeMaster" nocase ascii wide

    condition:
        any of them
}