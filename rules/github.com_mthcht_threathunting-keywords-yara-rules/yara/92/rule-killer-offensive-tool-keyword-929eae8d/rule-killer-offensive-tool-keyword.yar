rule rule_killer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'killer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_killer_offensive_tool_keyword = /\skiller\.cpp\s/ nocase ascii wide
                        $string2_killer_offensive_tool_keyword = /\skiller\.exe/ nocase ascii wide
                        $string3_killer_offensive_tool_keyword = /\sreverse\-shellcode\.cpp/ nocase ascii wide
                        $string4_killer_offensive_tool_keyword = /\sshellcode\-xor\.py/ nocase ascii wide
                        $string5_killer_offensive_tool_keyword = /\/killer\.exe/ nocase ascii wide
                        $string6_killer_offensive_tool_keyword = /\/Killer\.git/ nocase ascii wide
                        $string7_killer_offensive_tool_keyword = /\/OUT\:killer\.exe/ nocase ascii wide
                        $string8_killer_offensive_tool_keyword = /\/reverse\-shellcode\.cpp/ nocase ascii wide
                        $string9_killer_offensive_tool_keyword = /\/shellcode\-xor\.py/ nocase ascii wide
                        $string10_killer_offensive_tool_keyword = /\[\+\]\sDetecting\shooks\sin\snew\sntdll\smodule/ nocase ascii wide
                        $string11_killer_offensive_tool_keyword = /\\killer\.cpp/ nocase ascii wide
                        $string12_killer_offensive_tool_keyword = /\\killer\.exe/ nocase ascii wide
                        $string13_killer_offensive_tool_keyword = /\\nReversed\sshellcode\:\\n/ nocase ascii wide
                        $string14_killer_offensive_tool_keyword = /\\reverse\-shellcode\.cpp/ nocase ascii wide
                        $string15_killer_offensive_tool_keyword = /\\shellcode\-xor\.py/ nocase ascii wide
                        $string16_killer_offensive_tool_keyword = "0xHossam/Killer" nocase ascii wide
                        $string17_killer_offensive_tool_keyword = "26695658d9cd9108527921dc351de3b717d37d849d0390ad7b9a6f0bb4d474a9" nocase ascii wide
                        $string18_killer_offensive_tool_keyword = "3d0ab78d9ceb76cae4a8a600ebfcf3e078ccc5b19038edf73fcf9653f26d7064" nocase ascii wide
                        $string19_killer_offensive_tool_keyword = "Author => Hossam Ehab / EDR/AV evasion tool" nocase ascii wide
                        $string20_killer_offensive_tool_keyword = /Author\:\sHossam\sEhab\s\-\sfacebook\.com\/0xHossam/ nocase ascii wide
                        $string21_killer_offensive_tool_keyword = "b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9" nocase ascii wide
                        $string22_killer_offensive_tool_keyword = "c0e4815479886635396488093956d7926bcd803a4651c715398cf4446a05a55f" nocase ascii wide
                        $string23_killer_offensive_tool_keyword = "Hit enter to run shellcode/payload without creating a new thread" nocase ascii wide
                        $string24_killer_offensive_tool_keyword = /Hossam\sEhab\s\/\sAn\sEDR\s\(End\sPoint\sDetection\s\&\sResponse\)\sEvasion\sTool/ nocase ascii wide
                        $string25_killer_offensive_tool_keyword = "Killer tool for EDR/AV Evasion --> IAT Obfuscation" nocase ascii wide
                        $string26_killer_offensive_tool_keyword = /Sandbox\sdetected\s\-\sFilename\schanged\s\:\(\s/ nocase ascii wide
                        $string27_killer_offensive_tool_keyword = "Shellcode & key Decrypted after stomping" nocase ascii wide
                        $string28_killer_offensive_tool_keyword = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'\,/ nocase ascii wide
                        $string29_killer_offensive_tool_keyword = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide
                        $string30_killer_offensive_tool_keyword = "b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9" nocase ascii wide
                        $string31_killer_offensive_tool_keyword = "c40e57334fa15d54a9c0ebeb4345e3e2e9f26ba044b5fe923625a9f66e55c360" nocase ascii wide
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