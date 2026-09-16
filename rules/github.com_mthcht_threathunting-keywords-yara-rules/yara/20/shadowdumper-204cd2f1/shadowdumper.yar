rule ShadowDumper
{
    meta:
        description = "Detection patterns for the tool 'ShadowDumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowDumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\(SHADOW\sDUMPER\sv1\.0\)/ nocase ascii wide
                        $string2 = "/download/LsassDumping/" nocase ascii wide
                        $string3 = /\/ShadowDumper\.git/ nocase ascii wide
                        $string4 = "/ShadowDumper/releases/download/" nocase ascii wide
                        $string5 = /\\\\Public\\\\panda\.raw/ nocase ascii wide
                        $string6 = /\\\\Public\\\\simpleMDWD\.raw/ nocase ascii wide
                        $string7 = /\\\\Public\\\\sysMDWD\.file/ nocase ascii wide
                        $string8 = /\\Public\\panda\.raw/ nocase ascii wide
                        $string9 = /\\Public\\simpleMDWD\.raw/ nocase ascii wide
                        $string10 = /\\Public\\sysMDWD\.file/ nocase ascii wide
                        $string11 = /\\ShadowDumper\./ nocase ascii wide
                        $string12 = "34a3dda90725d2179dbb2bbead3e076cf7f2f6f5d7f93ec81c371f7640b034c4" nocase ascii wide
                        $string13 = "46D3E566-0EBA-4BD9-925E-84F4CB9EE7BC" nocase ascii wide
                        $string14 = "96920d601c95d13be934e071544eda074e9b36329e0b53735214519434aa41a0" nocase ascii wide
                        $string15 = /All\sDump\sfiles\swill\sbe\sstored\sin\sC\:\\\\Users\\\\Public/ nocase ascii wide
                        $string16 = /C\:\\\\Users\\\\DARKN3T\\\\Downloads/ nocase ascii wide
                        $string17 = /C\:\\\\Users\\\\Public\\\\callback\.el/ nocase ascii wide
                        $string18 = /Created\sby\sUsman\sSikander\s\(a\.k\.a\soffensive\-panda\)/ nocase ascii wide
                        $string19 = /Dump\slsass\.exe\susing\sMiniDumpWriteDump/ nocase ascii wide
                        $string20 = "Failed to create a dump of the forked process" nocase ascii wide
                        $string21 = "Failed to dump lsass" nocase ascii wide
                        $string22 = /Happy\sHacking.{0,100}Enjoy\sDump\!/ nocase ascii wide
                        $string23 = /MiniDumpWriteDump\(hLsass/ nocase ascii wide
                        $string24 = /MiniDumpWriteDump\(lsass/ nocase ascii wide
                        $string25 = "Offensive-Panda/ShadowDumper/" nocase ascii wide
                        $string26 = /ShadowDumper\.exe/ nocase ascii wide
                        $string27 = "To dump lsass memory using " nocase ascii wide
                        $string28 = /Users\\\\Public\\\\panda\.sense/ nocase ascii wide
                        $string29 = /Users\\Public\\callback\.el/ nocase ascii wide
                        $string30 = /Users\\Public\\panda\.sense/ nocase ascii wide
                        $string31 = "WELCOME TO MULTI-METHOD LSASS DUMPING TOOL" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}