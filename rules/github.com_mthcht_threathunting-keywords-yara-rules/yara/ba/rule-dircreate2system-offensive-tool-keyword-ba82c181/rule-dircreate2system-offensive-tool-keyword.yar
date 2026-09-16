rule rule_DirCreate2System_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DirCreate2System' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirCreate2System"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DirCreate2System_offensive_tool_keyword = /\/DirCreate2System\.git/ nocase ascii wide
                        $string2_DirCreate2System_offensive_tool_keyword = /\/DirCreate2System\.git/ nocase ascii wide
                        $string3_DirCreate2System_offensive_tool_keyword = /\[\+\]\sArbitrary\sDirectory\sCreation\sto\sSYSTEM\sShell\stechnique\s\!/ nocase ascii wide
                        $string4_DirCreate2System_offensive_tool_keyword = /\[\+\]\sFinding\sdirectory\sto\shijack/ nocase ascii wide
                        $string5_DirCreate2System_offensive_tool_keyword = /\[\+\]\sPoc\sBy\s\@404death\s/ nocase ascii wide
                        $string6_DirCreate2System_offensive_tool_keyword = /\[\+\]\sSpawning\sSYSTEM\sshell/ nocase ascii wide
                        $string7_DirCreate2System_offensive_tool_keyword = /\\dircreate2system\.pdb/ nocase ascii wide
                        $string8_DirCreate2System_offensive_tool_keyword = /\\dircreate2system\.sln/ nocase ascii wide
                        $string9_DirCreate2System_offensive_tool_keyword = /\\DirCreate2System\\bin\\/ nocase ascii wide
                        $string10_DirCreate2System_offensive_tool_keyword = "36c88f1852f3c162bf64d973bb6f69ffb7e22503015e104716fc51eaddcbe875" nocase ascii wide
                        $string11_DirCreate2System_offensive_tool_keyword = "765C5755-DBE9-4AB5-9427-921D0E46F9F0" nocase ascii wide
                        $string12_DirCreate2System_offensive_tool_keyword = "7EE536AE-6C1D-4881-88F7-37C8F2A0CA50" nocase ascii wide
                        $string13_DirCreate2System_offensive_tool_keyword = "binderlabs/DirCreate2System" nocase ascii wide
                        $string14_DirCreate2System_offensive_tool_keyword = "binderlabs/DirCreate2System" nocase ascii wide
                        $string15_DirCreate2System_offensive_tool_keyword = /cacls\sC\:\\Windows\\System32\\wermgr\.exe\.local\s\/e\s\/g\severyone\:f/ nocase ascii wide
                        $string16_DirCreate2System_offensive_tool_keyword = /dir_create2system\.txt/ nocase ascii wide
                        $string17_DirCreate2System_offensive_tool_keyword = /dircreate2system\.cpp/ nocase ascii wide
                        $string18_DirCreate2System_offensive_tool_keyword = /dircreate2system\.exe/ nocase ascii wide
                        $string19_DirCreate2System_offensive_tool_keyword = /dircreate2system\.vcxproj/ nocase ascii wide
                        $string20_DirCreate2System_offensive_tool_keyword = "DirCreate2System-main" nocase ascii wide
                        $string21_DirCreate2System_offensive_tool_keyword = /dll_spawn_cmd\.cpp/ nocase ascii wide
                        $string22_DirCreate2System_offensive_tool_keyword = /dll_spawn_cmd\.exe/ nocase ascii wide
                        $string23_DirCreate2System_offensive_tool_keyword = "ebfebca063aa056d7ffd8767c7c82d66c0c1a4339eb504a8e0636280dc5b839f" nocase ascii wide
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