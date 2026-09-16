rule rule_Dendrobate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dendrobate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dendrobate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dendrobate_offensive_tool_keyword = /\sDendron\.exe/ nocase ascii wide
                        $string2_Dendrobate_offensive_tool_keyword = /\/Bates\.csproj/ nocase ascii wide
                        $string3_Dendrobate_offensive_tool_keyword = /\/Dendrobate\.git/ nocase ascii wide
                        $string4_Dendrobate_offensive_tool_keyword = /\/Dendron\.bin/ nocase ascii wide
                        $string5_Dendrobate_offensive_tool_keyword = /\/Dendron\.csproj/ nocase ascii wide
                        $string6_Dendrobate_offensive_tool_keyword = /\/Dendron\.exe/ nocase ascii wide
                        $string7_Dendrobate_offensive_tool_keyword = /\/Dendron\.sln/ nocase ascii wide
                        $string8_Dendrobate_offensive_tool_keyword = /\/hDendron\.cs/ nocase ascii wide
                        $string9_Dendrobate_offensive_tool_keyword = /\\Dendrobate\\/ nocase ascii wide
                        $string10_Dendrobate_offensive_tool_keyword = /\\Dendron\.bin/ nocase ascii wide
                        $string11_Dendrobate_offensive_tool_keyword = /\\Dendron\.exe/ nocase ascii wide
                        $string12_Dendrobate_offensive_tool_keyword = /\\Dendron\.sln/ nocase ascii wide
                        $string13_Dendrobate_offensive_tool_keyword = /Bates\.exe\s\-\-kill/ nocase ascii wide
                        $string14_Dendrobate_offensive_tool_keyword = /Bates\.exe\s\-\-listen/ nocase ascii wide
                        $string15_Dendrobate_offensive_tool_keyword = "Dendrobate-master" nocase ascii wide
                        $string16_Dendrobate_offensive_tool_keyword = /dendron.{0,100}FileMonInject\.dll/ nocase ascii wide
                        $string17_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed.{0,100}InjectionLoader\.cs/ nocase ascii wide
                        $string18_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed.{0,100}WOW64Bypass\./ nocase ascii wide
                        $string19_Dendrobate_offensive_tool_keyword = /EasyHook\-Managed\/LocalHook\.cs/ nocase ascii wide
                        $string20_Dendrobate_offensive_tool_keyword = "FuzzySecurity/Dendrobate" nocase ascii wide
                        $string21_Dendrobate_offensive_tool_keyword = /ManagedEasyHook\.dll/ nocase ascii wide
                        $string22_Dendrobate_offensive_tool_keyword = /NativeEasyHook32\.dll/ nocase ascii wide
                        $string23_Dendrobate_offensive_tool_keyword = /NativeEasyHook64\.dll/ nocase ascii wide
                        $string24_Dendrobate_offensive_tool_keyword = "P8CuaPrgwBjunvZxJcgq" nocase ascii wide
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