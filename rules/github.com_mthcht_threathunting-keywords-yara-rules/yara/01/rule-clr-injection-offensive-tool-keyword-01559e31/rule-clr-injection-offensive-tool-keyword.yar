rule rule_CLR_Injection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CLR-Injection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CLR-Injection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CLR_Injection_offensive_tool_keyword = /\sCLR\-Injection_x64\.bat/ nocase ascii wide
                        $string2_CLR_Injection_offensive_tool_keyword = /\sCLR\-Injection_x86\.bat/ nocase ascii wide
                        $string3_CLR_Injection_offensive_tool_keyword = /\/CLR\-Injection\.git/ nocase ascii wide
                        $string4_CLR_Injection_offensive_tool_keyword = /\/CLR\-Injection_x64\.bat/ nocase ascii wide
                        $string5_CLR_Injection_offensive_tool_keyword = /\/CLR\-Injection_x86\.bat/ nocase ascii wide
                        $string6_CLR_Injection_offensive_tool_keyword = /\\CLR\-Injection_x64\.bat/ nocase ascii wide
                        $string7_CLR_Injection_offensive_tool_keyword = /\\CLR\-Injection_x86\.bat/ nocase ascii wide
                        $string8_CLR_Injection_offensive_tool_keyword = /\\CLR\-Injection\-main/ nocase ascii wide
                        $string9_CLR_Injection_offensive_tool_keyword = "3gstudent/CLR-Injection" nocase ascii wide
                        $string10_CLR_Injection_offensive_tool_keyword = "695d04c8162644e98cb0e68926b1cc9f47398e0ddd86255453c26b7619c88f10" nocase ascii wide
                        $string11_CLR_Injection_offensive_tool_keyword = "6cbd17824d093c835adebf81d9d2e3c1fd56db6dcec461c1cf72f0e3b5ba52f5" nocase ascii wide
                        $string12_CLR_Injection_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/.{0,1000}\/msg_x64\.dll/ nocase ascii wide
                        $string13_CLR_Injection_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/.{0,1000}\/test\/master\/msg\.dll/ nocase ascii wide
                        $string14_CLR_Injection_offensive_tool_keyword = /REG\.EXE\sADD\s.{0,1000}\s\/V\sThreadingModel\s\/T\sREG_SZ\s\/D\sApartment\s\/F/ nocase ascii wide
                        $string15_CLR_Injection_offensive_tool_keyword = /REG\.EXE\sADD\s.{0,1000}\s\/VE\s\/T\sREG_SZ\s\/D\s.{0,1000}\\msg\.dll/ nocase ascii wide
                        $string16_CLR_Injection_offensive_tool_keyword = /REG\.EXE\sADD\s.{0,1000}\s\/VE\s\/T\sREG_SZ\s\/D\s.{0,1000}\\msg_x64\.dll/ nocase ascii wide
                        $string17_CLR_Injection_offensive_tool_keyword = "wmic ENVIRONMENT create name=\"COR_ENABLE_PROFILING\",username=\"%username%\",VariableValue=\"1\"" nocase ascii wide
                        $string18_CLR_Injection_offensive_tool_keyword = /wmic\sENVIRONMENT\screate\sname\=\\"COR_PROFILER\\"\,username\=\\"\%username\%\\"\,VariableValue\=\\"\{11111111\-1111\-1111\-1111\-111111111111\}\\"/ nocase ascii wide

    condition:
        any of them
}