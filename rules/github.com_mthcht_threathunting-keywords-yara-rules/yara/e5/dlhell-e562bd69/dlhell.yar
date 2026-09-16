rule DLHell
{
    meta:
        description = "Detection patterns for the tool 'DLHell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLHell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDLHell\.py/ nocase ascii wide
                        $string2 = "## DLHell Main function" nocase ascii wide
                        $string3 = "#Dumps exported function from legit DLL using winedump" nocase ascii wide
                        $string4 = "#Removes previous hijacked dll" nocase ascii wide
                        $string5 = /\.py\s\s\-t\s.{0,1000}\.tpe\s\-c\s.{0,1000}\.exe.{0,1000}\s\-remote\-lib\s.{0,1000}\-remote\-target\s/ nocase ascii wide
                        $string6 = /\.py\s\-t\stemplate\.tpe\s\-c\s\'calc\.exe\'/ nocase ascii wide
                        $string7 = /\/DLHell\.git/ nocase ascii wide
                        $string8 = /\/DLHell\.py/ nocase ascii wide
                        $string9 = /\\DLHell\.py/ nocase ascii wide
                        $string10 = /\\DLHell\-main\\/ nocase ascii wide
                        $string11 = "Available ProgIDs and CLSIDs for DLL Hijacking:" nocase ascii wide
                        $string12 = /DLHell\sv2\.0/ nocase ascii wide
                        $string13 = /DLHell\.py\s\-/ nocase ascii wide
                        $string14 = "DLL Hell - DLL Proxifier/Hijacker" nocase ascii wide
                        $string15 = /dump_exported_functions\(library\,dll_orig\)/ nocase ascii wide
                        $string16 = "f47ae40fa2ba9ad689d59f8b755ea68e116c3dd603d6f985a7eff273ce0f381b" nocase ascii wide
                        $string17 = /impacket\.dcerpc\.v5/ nocase ascii wide
                        $string18 = /impacket\.smbconnection/ nocase ascii wide
                        $string19 = /kevin\.tellier\@synacktiv\.com/ nocase ascii wide
                        $string20 = "synacktiv/DLHell" nocase ascii wide

    condition:
        any of them
}