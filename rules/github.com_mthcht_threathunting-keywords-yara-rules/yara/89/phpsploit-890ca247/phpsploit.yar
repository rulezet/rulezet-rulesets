rule PhpSploit
{
    meta:
        description = "Detection patterns for the tool 'PhpSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhpSploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --get-backdoor" nocase ascii wide
                        $string2 = /\/phpsploit\.git/ nocase ascii wide
                        $string3 = "/phpsploit-config"
                        $string4 = /\\phpsploit\-main/ nocase ascii wide
                        $string5 = /\]\san\sup\-to\-date\sbackdoor\sis\sactive\son\s/ nocase ascii wide
                        $string6 = /0\.0\.0\.0\:23487/ nocase ascii wide
                        $string7 = /127\.0\.0\.1\/backdoored/ nocase ascii wide
                        $string8 = "13d43aebab981754164f99adb93874642147e449bc9da03d03932d3884ac5acb" nocase ascii wide
                        $string9 = "171f2fb14b88f54e6a6c233a81ee5183ef8f65d614fac527f303bda60a8dc533" nocase ascii wide
                        $string10 = "1ffbdfc67132f41d9dee443ebdb65b7cade592378cb846467c32f8984df4ab9b" nocase ascii wide
                        $string11 = "453c30c7c8d6c33e6f699d364016b8bae5ae5378e03e6e9966c17bbe9be9db33" nocase ascii wide
                        $string12 = "8847d2aebb87f30333220ad16142fc49469e5451533137686cb4d2760836c3a8" nocase ascii wide
                        $string13 = "a8dee73ae0015fdfeaeb4b58514db089a5881f26e01e94c83d685771f2577be4" nocase ascii wide
                        $string14 = "d2883841250ba0c96ce0e4095a612f0dd2c4419bb7e32f4873ac9da0c1053554" nocase ascii wide
                        $string15 = "exploit --get-backdoor" nocase ascii wide
                        $string16 = "fd1daf2fee0474c801fa389ad01576a42931f519ed59727388de4674c4643fc5" nocase ascii wide
                        $string17 = "nil0x42/phpsploit" nocase ascii wide
                        $string18 = "PhpSploit" nocase ascii wide
                        $string19 = /phpsploit\.txt/ nocase ascii wide
                        $string20 = "phpsploit_pipe exploit " nocase ascii wide
                        $string21 = "phpsploit_pipe process " nocase ascii wide
                        $string22 = "phpsploit_pipe set BROWSER" nocase ascii wide
                        $string23 = "phpsploit_pipe set PROXY " nocase ascii wide
                        $string24 = /phpsploit\-launcher\.sh/ nocase ascii wide
                        $string25 = /start_phpsploit_connected\.sh/ nocase ascii wide

    condition:
        any of them
}