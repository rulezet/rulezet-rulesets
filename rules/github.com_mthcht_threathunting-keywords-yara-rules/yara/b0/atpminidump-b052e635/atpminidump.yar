rule ATPMiniDump
{
    meta:
        description = "Detection patterns for the tool 'ATPMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ATPMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ATPMiniDump\.git/ nocase ascii wide
                        $string2 = /\[\!\]\sFailed\sto\screate\sminidump/ nocase ascii wide
                        $string3 = /\\dumpert\.dmp/ nocase ascii wide
                        $string4 = "0538b3096657777e14c5ac6296037b936df7fb375d32199b0ae1b7fe33b3d63b" nocase ascii wide
                        $string5 = "53a8f4b6cd47f980a97be192fdbf70c028065c7bfdf2e461927c7561eafbea6b" nocase ascii wide
                        $string6 = "920B8C5B-0DC5-4BD7-B6BB-D14B39BFC9FE" nocase ascii wide
                        $string7 = "ATPMiniDump" nocase ascii wide
                        $string8 = "b4rtik/ATPMiniDump" nocase ascii wide
                        $string9 = "By b4rtik & uf0" nocase ascii wide
                        $string10 = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase ascii wide
                        $string11 = "Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot" nocase ascii wide

    condition:
        any of them
}