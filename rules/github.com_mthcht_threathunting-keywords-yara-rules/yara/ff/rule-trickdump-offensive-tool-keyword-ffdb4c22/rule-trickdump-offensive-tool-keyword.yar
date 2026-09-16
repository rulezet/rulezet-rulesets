rule rule_TrickDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TrickDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TrickDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TrickDump_offensive_tool_keyword = /\/TrickDump\.git/ nocase ascii wide
                        $string2_TrickDump_offensive_tool_keyword = /\\Barrel\.exe\sdebugproc/ nocase ascii wide
                        $string3_TrickDump_offensive_tool_keyword = /\\Lock\.exe\sdisk/ nocase ascii wide
                        $string4_TrickDump_offensive_tool_keyword = /\\Shock\.exe\sknowndlls/ nocase ascii wide
                        $string5_TrickDump_offensive_tool_keyword = /\\temp\\trick\.zip.{0,1000}\.json/ nocase ascii wide
                        $string6_TrickDump_offensive_tool_keyword = /\\TrickDump\.sln/ nocase ascii wide
                        $string7_TrickDump_offensive_tool_keyword = /\\TrickDump\-main/ nocase ascii wide
                        $string8_TrickDump_offensive_tool_keyword = /\>Shock\.exe\</ nocase ascii wide
                        $string9_TrickDump_offensive_tool_keyword = /\>Trick\.exe\</ nocase ascii wide
                        $string10_TrickDump_offensive_tool_keyword = "12bc134420da64f0ff3a93d3a1ca6376677ae9c0494b545173bf20e45787e873" nocase ascii wide
                        $string11_TrickDump_offensive_tool_keyword = "2010807d09f45f949a2e24615d58a15d8914e09f9988aa8fd7c863c7e5434aa8" nocase ascii wide
                        $string12_TrickDump_offensive_tool_keyword = "4957a3e8d46d84698c5987e2c45bc2705865ac8cf742218c574de4cee69da080" nocase ascii wide
                        $string13_TrickDump_offensive_tool_keyword = "9E9BB94C-1FBE-4D0B-83B7-E42C83FC5D45" nocase ascii wide
                        $string14_TrickDump_offensive_tool_keyword = "B92B6B67-C7C8-4548-85EE-A215D74C000D" nocase ascii wide
                        $string15_TrickDump_offensive_tool_keyword = "by @ricardojoserf" nocase ascii wide
                        $string16_TrickDump_offensive_tool_keyword = "C666C98C-84C3-4A5A-A73B-2FC711CFCB7F" nocase ascii wide
                        $string17_TrickDump_offensive_tool_keyword = "d2888f1714566be066719ca2bcbe9e5948a002a7f12070397b306e96442c26aa" nocase ascii wide
                        $string18_TrickDump_offensive_tool_keyword = "D8FC3807-CEAA-4F6A-9C8F-CC96F99D1F04" nocase ascii wide
                        $string19_TrickDump_offensive_tool_keyword = "e4bc4fc4b8f65caedc7302900804da6af5689a7f3a03b31ae62433b24f393568" nocase ascii wide
                        $string20_TrickDump_offensive_tool_keyword = /go\sbuild\slock\.go\s\&\&\sgo\sbuild\sshock\.go\s\&\&\sgo\sbuild\sbarrel\.go/ nocase ascii wide
                        $string21_TrickDump_offensive_tool_keyword = /go\srun\slock\.go\s\-o\sdisk/ nocase ascii wide
                        $string22_TrickDump_offensive_tool_keyword = /go\srun\sshock\.go\s\-o\sknwondlls/ nocase ascii wide
                        $string23_TrickDump_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/ntdll\.dll/ nocase ascii wide
                        $string24_TrickDump_offensive_tool_keyword = /nuitka\s\-\-onefile\sbarrel\.py/ nocase ascii wide
                        $string25_TrickDump_offensive_tool_keyword = /nuitka\s\-\-onefile\slock\.py/ nocase ascii wide
                        $string26_TrickDump_offensive_tool_keyword = /nuitka\s\-\-onefile\sshock\.py/ nocase ascii wide
                        $string27_TrickDump_offensive_tool_keyword = /pyinstaller\s\-F\sbarrel\.py/ nocase ascii wide
                        $string28_TrickDump_offensive_tool_keyword = /pyinstaller\s\-F\slock\.py/ nocase ascii wide
                        $string29_TrickDump_offensive_tool_keyword = /pyinstaller\s\-F\sshock\.py/ nocase ascii wide
                        $string30_TrickDump_offensive_tool_keyword = /python\sbarrel\.go\s\-o\sdebugproc/ nocase ascii wide
                        $string31_TrickDump_offensive_tool_keyword = /python\sbarrel\.py\s\-o\sdebugproc/ nocase ascii wide
                        $string32_TrickDump_offensive_tool_keyword = /python\screate_dump\.py\s/ nocase ascii wide
                        $string33_TrickDump_offensive_tool_keyword = /python\slock\.py\s\-o\sdisk/ nocase ascii wide
                        $string34_TrickDump_offensive_tool_keyword = /python\sshock\.py\s\-o\sknwondlls/ nocase ascii wide
                        $string35_TrickDump_offensive_tool_keyword = /python\.exe.{0,1000}\screate_dump\.py\s/ nocase ascii wide
                        $string36_TrickDump_offensive_tool_keyword = /python3\screate_dump\.py\s/ nocase ascii wide
                        $string37_TrickDump_offensive_tool_keyword = /python3\.exe.{0,1000}\screate_dump\.py\s/ nocase ascii wide
                        $string38_TrickDump_offensive_tool_keyword = "ricardojoserf/TrickDump" nocase ascii wide

    condition:
        any of them
}