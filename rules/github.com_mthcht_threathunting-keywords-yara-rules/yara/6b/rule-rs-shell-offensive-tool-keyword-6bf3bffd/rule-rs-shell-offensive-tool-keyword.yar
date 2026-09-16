rule rule_rs_shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rs-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rs-shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rs_shell_offensive_tool_keyword = /\/rs\-shell\.exe/ nocase ascii wide
                        $string2_rs_shell_offensive_tool_keyword = /\/rs\-shell\.git/ nocase ascii wide
                        $string3_rs_shell_offensive_tool_keyword = "/rs-shell/zipball/" nocase ascii wide
                        $string4_rs_shell_offensive_tool_keyword = "/rs-shell-linux "
                        $string5_rs_shell_offensive_tool_keyword = /\/rs\-shell\-windows\.exe/ nocase ascii wide
                        $string6_rs_shell_offensive_tool_keyword = /\\https_windows_implant\.rs/ nocase ascii wide
                        $string7_rs_shell_offensive_tool_keyword = /\\rs\-shell\.exe/ nocase ascii wide
                        $string8_rs_shell_offensive_tool_keyword = /\\rs\-shell\-windows\.exe/ nocase ascii wide
                        $string9_rs_shell_offensive_tool_keyword = "0d2f5c4ee9f63b465776329c0ad2c94cbad788db383a0d94c0219a64d7f55d46" nocase ascii wide
                        $string10_rs_shell_offensive_tool_keyword = "1e661c6d9386dfb181a8c538c3f0b6c5531f9986ad0564eee847ac917430403a" nocase ascii wide
                        $string11_rs_shell_offensive_tool_keyword = "2062837ed59e6bfda4b2b98be75c37f17e6f8e9dec7cce754609cd249b4d02e3" nocase ascii wide
                        $string12_rs_shell_offensive_tool_keyword = "32292398eca5d75150f89d07a622728e52302a73573ec7e1a28268dbe5079ac2" nocase ascii wide
                        $string13_rs_shell_offensive_tool_keyword = "3fb111c19e638174ed630c9a9d8d999c1bf62d2308a8284fedad1efab45a7f96" nocase ascii wide
                        $string14_rs_shell_offensive_tool_keyword = "5f01feb0f870564dae6ef4741dc3b0e200517ea1d712d095a67f4c84bc922bea" nocase ascii wide
                        $string15_rs_shell_offensive_tool_keyword = "78d6cc62452627889988e7d1d63675ee70a4cea3657631d55afb62467630c954" nocase ascii wide
                        $string16_rs_shell_offensive_tool_keyword = "831d87d48fde985447d82a0dbde6a720ecb4c882e28af0bde713b6b340e5b8e3" nocase ascii wide
                        $string17_rs_shell_offensive_tool_keyword = "86dd7c02ed1f529e5c2ec48b1da08d2570769caaa8250aaf5c4438e2aa5558a6" nocase ascii wide
                        $string18_rs_shell_offensive_tool_keyword = "8e122c687fec626c06bd82a2141ea1c49b262ed8e6d93b95583dbe46811b1629" nocase ascii wide
                        $string19_rs_shell_offensive_tool_keyword = "b5e8ccde03661cc33cc84e5cfd81badadb23a4d25a4117a92254c029c40d9c5a" nocase ascii wide
                        $string20_rs_shell_offensive_tool_keyword = "b8328fa4f70b5252b4d5850b540953a7766483b7c710f4fef68186662849f040" nocase ascii wide
                        $string21_rs_shell_offensive_tool_keyword = "BlWasp/rs-shell" nocase ascii wide
                        $string22_rs_shell_offensive_tool_keyword = /BlWasp\/syscalls\-rs\.git/ nocase ascii wide
                        $string23_rs_shell_offensive_tool_keyword = "d4deb85a5856036a50fc97fd185a545ec437604a64c0c0f7dfe9b7c81265558c" nocase ascii wide
                        $string24_rs_shell_offensive_tool_keyword = "db1288eace30cc5f6f942df1596f94ba846ed8fee9772ad68fc45a5efac6d6db" nocase ascii wide
                        $string25_rs_shell_offensive_tool_keyword = "ebc3a8b952bb617b89cf6f807c4e60e23978608dcaa75e381406bd85de984481" nocase ascii wide
                        $string26_rs_shell_offensive_tool_keyword = "f0f1873d2b61cd03c1daa52ec0cb279676b118507c9031e26d132b8f4187b2bd" nocase ascii wide
                        $string27_rs_shell_offensive_tool_keyword = "f81c9762e91fbd65cd1a3ca1098b36cba4c07f1eeebb4476900b312c955e30e0" nocase ascii wide
                        $string28_rs_shell_offensive_tool_keyword = "ff7a51c653501cfce1fd9198391441d7bad21a11bd75a905479682c0a00cb846" nocase ascii wide
                        $string29_rs_shell_offensive_tool_keyword = /rs\-shell\.exe\s\-m\s/ nocase ascii wide

    condition:
        any of them
}