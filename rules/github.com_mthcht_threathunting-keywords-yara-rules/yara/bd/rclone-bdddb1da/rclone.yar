rule rclone
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Behavior\:Linux\/SuspRcloneSpawn\.A/ nocase ascii wide
                        $string2 = /Behavior\:Linux\/SuspRcloneSpawn\.B/ nocase ascii wide
                        $string3 = "Behavior:Win32/OFNRclone" nocase ascii wide
                        $string4 = /Behavior\:Win32\/PShellRclone\.SA/ nocase ascii wide
                        $string5 = /Behavior\:Win32\/RcloneConf\.A/ nocase ascii wide
                        $string6 = /Behavior\:Win32\/RcloneExfil\.S/ nocase ascii wide
                        $string7 = /Behavior\:Win32\/RcloneExfil\.SA/ nocase ascii wide
                        $string8 = /Behavior\:Win32\/RcloneMega\.SA\!Ofn/ nocase ascii wide
                        $string9 = /Behavior\:Win32\/RcloneMega\.SA/ nocase ascii wide
                        $string10 = /Behavior\:Win32\/RcloneSusExec\.A/ nocase ascii wide
                        $string11 = /Behavior\:Win32\/RcloneSusTLD\.A/ nocase ascii wide
                        $string12 = /Behavior\:Win32\/RcloneUAgent\.A/ nocase ascii wide
                        $string13 = /Behavior\:Win32\/RenamedToolRclone\.SA/ nocase ascii wide
                        $string14 = /Behavior\:Win32\/SuspRclone\.A/ nocase ascii wide
                        $string15 = /Behavior\:Win32\/SuspRclone\.B/ nocase ascii wide
                        $string16 = /Behavior\:Win32\/SuspRclone\.C/ nocase ascii wide
                        $string17 = /Behavior\:Win32\/SuspRclone\.D/ nocase ascii wide
                        $string18 = "HackTool:Win64/FakeRclone" nocase ascii wide
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