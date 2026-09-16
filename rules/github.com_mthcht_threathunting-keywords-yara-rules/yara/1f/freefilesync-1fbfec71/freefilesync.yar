rule freefilesync
{
    meta:
        description = "Detection patterns for the tool 'freefilesync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "freefilesync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/FreeFileSync\.exe/ nocase ascii wide
                        $string2 = /\/FreeFileSync\.tar\.gz/ nocase ascii wide
                        $string3 = /\/FreeFileSync_.{0,100}\.tar\.gz/ nocase ascii wide
                        $string4 = /\/FreeFileSync_.{0,100}_Windows_Setup\.exe/ nocase ascii wide
                        $string5 = /\/FreeFileSync_x64\.exe/ nocase ascii wide
                        $string6 = /\/FreeFileSyncPortable_.{0,100}\.exe/ nocase ascii wide
                        $string7 = /\/RealTimeSync\.exe/ nocase ascii wide
                        $string8 = "/tmp/FreeFileSync"
                        $string9 = /\\AppData\\Roaming\\FreeFileSync\\Logs\\/ nocase ascii wide
                        $string10 = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
                        $string11 = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
                        $string12 = /\\FreeFileSync\.exe/ nocase ascii wide
                        $string13 = /\\FreeFileSync\\Logs\\/ nocase ascii wide
                        $string14 = /\\FreeFileSync_.{0,100}_Windows_Setup\.exe/ nocase ascii wide
                        $string15 = /\\FreeFileSync_x64\.exe/ nocase ascii wide
                        $string16 = /\\FreeFileSyncPortable_.{0,100}\.exe/ nocase ascii wide
                        $string17 = /\\Program\sFiles\\FreeFileSync/ nocase ascii wide
                        $string18 = /\\RealTimeSync\.exe/ nocase ascii wide
                        $string19 = /\\WOW6432Node\\FreeFileSync/ nocase ascii wide
                        $string20 = ">FreeFileSync - Folder Comparison and Synchronization<" nocase ascii wide
                        $string21 = ">FreeFileSync Setup<" nocase ascii wide
                        $string22 = ">FreeFileSync<" nocase ascii wide
                        $string23 = "0b0977a047ea3397c83d19f0edeef003c98021a2f64b03503f67a7189aeab4bf" nocase ascii wide
                        $string24 = "13b6443f4e1f03bc7c37fe9d260435886ad80ee292c0a3b5b9cdeb763576e31b" nocase ascii wide
                        $string25 = /api\.freefilesync\.org/ nocase ascii wide
                        $string26 = "c888fa7aadb304362df7bcb43164b6a07222739f5d2a90bf475817aa0e75013d" nocase ascii wide
                        $string27 = /\-Command\sAdd\-MpPreference\s\-ExclusionProcess\s.{0,100}\\Program\sFiles\\FreeFileSync\\Bin\\/ nocase ascii wide
                        $string28 = "fb4d282f8d202006d682eef84a83757376c20929f62626e288a159d730fde3c9" nocase ascii wide
                        $string29 = /https\:\/\/api\.freefilesync\.org\/new_installation/ nocase ascii wide
                        $string30 = /https\:\/\/freefilesync\.org\/donate/ nocase ascii wide
                        $string31 = "pkill FreeFileSync" nocase ascii wide
                        $string32 = "pkill RealTimeSync" nocase ascii wide
                        $string33 = /SOFTWARE\\WOW6432Node\\FreeFileSync/ nocase ascii wide
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