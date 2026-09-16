rule rule_LOLSpoof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LOLSpoof_offensive_tool_keyword = "# Find LOLBin and reconstruct commandline" nocase ascii wide
                        $string2_LOLSpoof_offensive_tool_keyword = /\/lolbin\.exe/ nocase ascii wide
                        $string3_LOLSpoof_offensive_tool_keyword = /\/LOLSpoof\.git/ nocase ascii wide
                        $string4_LOLSpoof_offensive_tool_keyword = /\/LOLSpoof\.nim/ nocase ascii wide
                        $string5_LOLSpoof_offensive_tool_keyword = "/LOLSpoof/releases/download/" nocase ascii wide
                        $string6_LOLSpoof_offensive_tool_keyword = /\[LOLSpoof\]\s\>\s/ nocase ascii wide
                        $string7_LOLSpoof_offensive_tool_keyword = /\\lolbin\.exe/ nocase ascii wide
                        $string8_LOLSpoof_offensive_tool_keyword = /\\LOLSpoof\.nim/ nocase ascii wide
                        $string9_LOLSpoof_offensive_tool_keyword = /\\LOLSpoof\\/ nocase ascii wide
                        $string10_LOLSpoof_offensive_tool_keyword = "159766fade72711fc8b28004ec1f2088bb837852029f1e79446d728728c235ef" nocase ascii wide
                        $string11_LOLSpoof_offensive_tool_keyword = "8310f53135ddcc2e6b9fd6ca2aca3662f61dc1b5fb2b2510fa762e5862afcf94" nocase ascii wide
                        $string12_LOLSpoof_offensive_tool_keyword = "84f94c746a47d8bee6663a57051e15ce80f6847dc66733c31b1d793301814fcb" nocase ascii wide
                        $string13_LOLSpoof_offensive_tool_keyword = "An interactive shell to spoof some LOLBins" nocase ascii wide
                        $string14_LOLSpoof_offensive_tool_keyword = "Could not spoof binary: " nocase ascii wide
                        $string15_LOLSpoof_offensive_tool_keyword = "f8d85258f9c717fb629942c43b2218c96800252c3da18cbbc11839f790acc452" nocase ascii wide
                        $string16_LOLSpoof_offensive_tool_keyword = "itaymigdal/LOLSpoof" nocase ascii wide
                        $string17_LOLSpoof_offensive_tool_keyword = /lolbin\.exe\s/ nocase ascii wide
                        $string18_LOLSpoof_offensive_tool_keyword = /LOLSpoof\.exe/ nocase ascii wide
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