rule TrickDump
{
    meta:
        description = "Detection patterns for the tool 'TrickDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TrickDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/TrickDump\.git/ nocase ascii wide
                        $string2 = /\\Barrel\.exe\sdebugproc/ nocase ascii wide
                        $string3 = /\\Lock\.exe\sdisk/ nocase ascii wide
                        $string4 = /\\Shock\.exe\sknowndlls/ nocase ascii wide
                        $string5 = /\\temp\\trick\.zip.{0,1000}\.json/ nocase ascii wide
                        $string6 = /\\TrickDump\.sln/ nocase ascii wide
                        $string7 = /\\TrickDump\-main/ nocase ascii wide
                        $string8 = /\>Shock\.exe\</ nocase ascii wide
                        $string9 = /\>Trick\.exe\</ nocase ascii wide
                        $string10 = "12bc134420da64f0ff3a93d3a1ca6376677ae9c0494b545173bf20e45787e873" nocase ascii wide
                        $string11 = "2010807d09f45f949a2e24615d58a15d8914e09f9988aa8fd7c863c7e5434aa8" nocase ascii wide
                        $string12 = "4957a3e8d46d84698c5987e2c45bc2705865ac8cf742218c574de4cee69da080" nocase ascii wide
                        $string13 = "9E9BB94C-1FBE-4D0B-83B7-E42C83FC5D45" nocase ascii wide
                        $string14 = "B92B6B67-C7C8-4548-85EE-A215D74C000D" nocase ascii wide
                        $string15 = "by @ricardojoserf" nocase ascii wide
                        $string16 = "C666C98C-84C3-4A5A-A73B-2FC711CFCB7F" nocase ascii wide
                        $string17 = "d2888f1714566be066719ca2bcbe9e5948a002a7f12070397b306e96442c26aa" nocase ascii wide
                        $string18 = "D8FC3807-CEAA-4F6A-9C8F-CC96F99D1F04" nocase ascii wide
                        $string19 = "e4bc4fc4b8f65caedc7302900804da6af5689a7f3a03b31ae62433b24f393568" nocase ascii wide
                        $string20 = /go\sbuild\slock\.go\s\&\&\sgo\sbuild\sshock\.go\s\&\&\sgo\sbuild\sbarrel\.go/ nocase ascii wide
                        $string21 = /go\srun\slock\.go\s\-o\sdisk/ nocase ascii wide
                        $string22 = /go\srun\sshock\.go\s\-o\sknwondlls/ nocase ascii wide
                        $string23 = /http\:\/\/127\.0\.0\.1\/ntdll\.dll/ nocase ascii wide
                        $string24 = /nuitka\s\-\-onefile\sbarrel\.py/ nocase ascii wide
                        $string25 = /nuitka\s\-\-onefile\slock\.py/ nocase ascii wide
                        $string26 = /nuitka\s\-\-onefile\sshock\.py/ nocase ascii wide
                        $string27 = /pyinstaller\s\-F\sbarrel\.py/ nocase ascii wide
                        $string28 = /pyinstaller\s\-F\slock\.py/ nocase ascii wide
                        $string29 = /pyinstaller\s\-F\sshock\.py/ nocase ascii wide
                        $string30 = /python\sbarrel\.go\s\-o\sdebugproc/ nocase ascii wide
                        $string31 = /python\sbarrel\.py\s\-o\sdebugproc/ nocase ascii wide
                        $string32 = /python\screate_dump\.py\s/ nocase ascii wide
                        $string33 = /python\slock\.py\s\-o\sdisk/ nocase ascii wide
                        $string34 = /python\sshock\.py\s\-o\sknwondlls/ nocase ascii wide
                        $string35 = /python\.exe.{0,1000}\screate_dump\.py\s/ nocase ascii wide
                        $string36 = /python3\screate_dump\.py\s/ nocase ascii wide
                        $string37 = /python3\.exe.{0,1000}\screate_dump\.py\s/ nocase ascii wide
                        $string38 = "ricardojoserf/TrickDump" nocase ascii wide

    condition:
        any of them
}