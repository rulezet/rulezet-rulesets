rule SharpEDRChecker
{
    meta:
        description = "Detection patterns for the tool 'SharpEDRChecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEDRChecker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " SharpEDRChecker" nocase ascii wide
                        $string2 = /\/SharpEDRChecker\-.{0,100}\.zip/ nocase ascii wide
                        $string3 = /\/SharpEDRChecker\.git/ nocase ascii wide
                        $string4 = "/SharpEDRChecker/" nocase ascii wide
                        $string5 = /\[\!\]\[\!\]\[\!\]\sChecking\sDirectories\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string6 = /\[\!\]\[\!\]\[\!\]\sChecking\sdrivers\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string7 = /\[\!\]\[\!\]\[\!\]\sChecking\smodules\sloaded\sin\syour\scurrent\sprocess\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string8 = /\[\!\]\[\!\]\[\!\]\sChecking\sServices\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string9 = /\[\!\]\[\!\]\[\!\]\sEDR\sChecks\sComplete\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string10 = /\[\!\]\[\!\]\[\!\]\sWelcome\sto\sSharpEDRChecker\sby\s\@PwnDexter\s\[\!\]\[\!\]\[\!\]/ nocase ascii wide
                        $string11 = /\\SharpEDRChecker\-.{0,100}\.zip/ nocase ascii wide
                        $string12 = /\\SharpEDRChecker\.cs/ nocase ascii wide
                        $string13 = /\\SharpEDRChecker\.sln/ nocase ascii wide
                        $string14 = /\\SharpEDRChecker\\/ nocase ascii wide
                        $string15 = "14e8721290b9457ec4c641c48aaa111df18eeed8e1c208da18666d3f3dd8e2ff" nocase ascii wide
                        $string16 = "BDFEE233-3FED-42E5-AA64-492EB2AC7047" nocase ascii wide
                        $string17 = "e3038dfa23e4c4707e73f5b4a214fe35796b805ef213e0e84da1e20cd5643fa5" nocase ascii wide
                        $string18 = "Invoke-EDRChecker" nocase ascii wide
                        $string19 = "PwnDexter/SharpEDRChecker" nocase ascii wide
                        $string20 = /SharpEDRChecker\.exe/ nocase ascii wide
                        $string21 = /SharpEDRChecker\.Program/ nocase ascii wide
                        $string22 = "SharpEDRChecker/releases" nocase ascii wide
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