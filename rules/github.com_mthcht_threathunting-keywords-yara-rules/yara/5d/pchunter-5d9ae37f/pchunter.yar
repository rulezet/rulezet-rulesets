rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/PCHunter\.exe/ nocase ascii wide
                        $string2 = /\/PCHunter_free\.zip/ nocase ascii wide
                        $string3 = /\\AppData\\Local\\Temp\\PCHunter\.sys/ nocase ascii wide
                        $string4 = /\\ControlSet001\\Services\\PCHunter/ nocase ascii wide
                        $string5 = /\\PCHunter\.exe/ nocase ascii wide
                        $string6 = /\\PCHunter_free\.zip/ nocase ascii wide
                        $string7 = /\\PCHunter32\.pdb/ nocase ascii wide
                        $string8 = /\\PCHunter64ar\.sys/ nocase ascii wide
                        $string9 = ">Epoolsoft Windows Information View Tools<" nocase ascii wide
                        $string10 = ">PC Hunter<" nocase ascii wide
                        $string11 = /\>PCHunter\.sys\</ nocase ascii wide
                        $string12 = "648eaadf2d81af9ea6792d48740aa3ef4787303f95a0e2abaf23b87b13758eb7" nocase ascii wide
                        $string13 = /http\:\/\/www\.epoolsoft\.com\/pchunter\/pchunter_free/ nocase ascii wide
                        $string14 = /http\:\/\/www\.epoolsoft\.com\/PCHunter_Standard/ nocase ascii wide
                        $string15 = /https\:\/\/www\.majorgeeks\.com\/files\/details\/pc_hunter\.html/ nocase ascii wide
                        $string16 = "PC Hunter Standard" nocase ascii wide
                        $string17 = /PCHunter32\.exe/ nocase ascii wide
                        $string18 = /PCHunter64\.exe/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}