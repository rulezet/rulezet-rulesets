rule rule_PhpSploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PhpSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhpSploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PhpSploit_offensive_tool_keyword = " --get-backdoor" nocase ascii wide
                        $string2_PhpSploit_offensive_tool_keyword = /\/phpsploit\.git/ nocase ascii wide
                        $string3_PhpSploit_offensive_tool_keyword = "/phpsploit-config"
                        $string4_PhpSploit_offensive_tool_keyword = /\\phpsploit\-main/ nocase ascii wide
                        $string5_PhpSploit_offensive_tool_keyword = /\]\san\sup\-to\-date\sbackdoor\sis\sactive\son\s/ nocase ascii wide
                        $string6_PhpSploit_offensive_tool_keyword = /0\.0\.0\.0\:23487/ nocase ascii wide
                        $string7_PhpSploit_offensive_tool_keyword = /127\.0\.0\.1\/backdoored/ nocase ascii wide
                        $string8_PhpSploit_offensive_tool_keyword = "13d43aebab981754164f99adb93874642147e449bc9da03d03932d3884ac5acb" nocase ascii wide
                        $string9_PhpSploit_offensive_tool_keyword = "171f2fb14b88f54e6a6c233a81ee5183ef8f65d614fac527f303bda60a8dc533" nocase ascii wide
                        $string10_PhpSploit_offensive_tool_keyword = "1ffbdfc67132f41d9dee443ebdb65b7cade592378cb846467c32f8984df4ab9b" nocase ascii wide
                        $string11_PhpSploit_offensive_tool_keyword = "453c30c7c8d6c33e6f699d364016b8bae5ae5378e03e6e9966c17bbe9be9db33" nocase ascii wide
                        $string12_PhpSploit_offensive_tool_keyword = "8847d2aebb87f30333220ad16142fc49469e5451533137686cb4d2760836c3a8" nocase ascii wide
                        $string13_PhpSploit_offensive_tool_keyword = "a8dee73ae0015fdfeaeb4b58514db089a5881f26e01e94c83d685771f2577be4" nocase ascii wide
                        $string14_PhpSploit_offensive_tool_keyword = "d2883841250ba0c96ce0e4095a612f0dd2c4419bb7e32f4873ac9da0c1053554" nocase ascii wide
                        $string15_PhpSploit_offensive_tool_keyword = "exploit --get-backdoor" nocase ascii wide
                        $string16_PhpSploit_offensive_tool_keyword = "fd1daf2fee0474c801fa389ad01576a42931f519ed59727388de4674c4643fc5" nocase ascii wide
                        $string17_PhpSploit_offensive_tool_keyword = "nil0x42/phpsploit" nocase ascii wide
                        $string18_PhpSploit_offensive_tool_keyword = "PhpSploit" nocase ascii wide
                        $string19_PhpSploit_offensive_tool_keyword = /phpsploit\.txt/ nocase ascii wide
                        $string20_PhpSploit_offensive_tool_keyword = "phpsploit_pipe exploit " nocase ascii wide
                        $string21_PhpSploit_offensive_tool_keyword = "phpsploit_pipe process " nocase ascii wide
                        $string22_PhpSploit_offensive_tool_keyword = "phpsploit_pipe set BROWSER" nocase ascii wide
                        $string23_PhpSploit_offensive_tool_keyword = "phpsploit_pipe set PROXY " nocase ascii wide
                        $string24_PhpSploit_offensive_tool_keyword = /phpsploit\-launcher\.sh/ nocase ascii wide
                        $string25_PhpSploit_offensive_tool_keyword = /start_phpsploit_connected\.sh/ nocase ascii wide

    condition:
        any of them
}