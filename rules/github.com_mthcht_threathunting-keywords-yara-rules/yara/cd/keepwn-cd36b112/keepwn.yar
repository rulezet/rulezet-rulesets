rule KeePwn
{
    meta:
        description = "Detection patterns for the tool 'KeePwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeePwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-bruteforce\s.{0,100}\.kdbx/ nocase ascii wide
                        $string2 = /\s\-\-dump_file\sKeepass\.exe\.dmp/ nocase ascii wide
                        $string3 = /\sKeePwn\.py/ nocase ascii wide
                        $string4 = /\s\-\-plugin\sKeeFarceRebornPlugin\.dll/ nocase ascii wide
                        $string5 = /\/keepwn\.core\./ nocase ascii wide
                        $string6 = /\/KeePwn\.git/ nocase ascii wide
                        $string7 = /\/KeePwn\.py/ nocase ascii wide
                        $string8 = /\/keepwn\.utils\./ nocase ascii wide
                        $string9 = "/KeePwn/keepwn/" nocase ascii wide
                        $string10 = "/KeePwn/tarball/" nocase ascii wide
                        $string11 = "/KeePwn/zipball/" nocase ascii wide
                        $string12 = /\/KeePwn\-0\.3\// nocase ascii wide
                        $string13 = /\\KeePwn\.py/ nocase ascii wide
                        $string14 = /\\KeePwn\\keepwn\\/ nocase ascii wide
                        $string15 = /\\KeePwn\-0\.3\\/ nocase ascii wide
                        $string16 = /\\KeePwn\-main\\/ nocase ascii wide
                        $string17 = "0971aee212257aba1a537747e492b76aff0020623edb68defd378e8ed069f6a8" nocase ascii wide
                        $string18 = "161451349be662c5c649be01c670f86b233fb08a1c77c9b720ea08b622d04964" nocase ascii wide
                        $string19 = "2c71dd5b47601d4b105d8da7007511045dd58f5d71b997290209d55f20dce887" nocase ascii wide
                        $string20 = "39a9f25d64ef416e4be4fadf6fae1b2169bfeb02501be443e8af1fec17412f60" nocase ascii wide
                        $string21 = "83803142d36f4e09346394ae2038353977bd16389fd80e09dc7fc1e8850e1365" nocase ascii wide
                        $string22 = "8793997d31b23280ec1a46ff7fd065a6510ea66fcbf12651583244805e958212" nocase ascii wide
                        $string23 = "a8fca4711a214b5b154a7a9f31018bff0eb59ddc8dfe8bad04dde7f90972437a" nocase ascii wide
                        $string24 = "b7b67e33ca53799aa1be6a7aa7677363b8a0e711091bccd2e49f501d5dc22de7" nocase ascii wide
                        $string25 = /d3lb3\@protonmail\.com/ nocase ascii wide
                        $string26 = "e3bd611e8aa3d18d81944ebdabf51ce9aed8eb414a95ee8eb6d45ca0ebd58003" nocase ascii wide
                        $string27 = "keepass-password-dumper" nocase ascii wide
                        $string28 = "KeePwn --" nocase ascii wide
                        $string29 = "KeePwn parse_dump " nocase ascii wide
                        $string30 = "KeePwn plugin " nocase ascii wide
                        $string31 = "KeePwn trigger " nocase ascii wide
                        $string32 = /KeePwn\sv.{0,100}\s\-\sby\sJulien\sBEDEL/ nocase ascii wide
                        $string33 = /keepwn\.__main__\:main/ nocase ascii wide
                        $string34 = /keepwn\.core\./ nocase ascii wide
                        $string35 = /keepwn\.core\.parse_dump/ nocase ascii wide
                        $string36 = /keepwn\.core\.plugin/ nocase ascii wide
                        $string37 = /keepwn\.core\.search/ nocase ascii wide
                        $string38 = /keepwn\.core\.trigger/ nocase ascii wide
                        $string39 = /KeePwn\.py\s/ nocase ascii wide
                        $string40 = /keepwn\.utils\./ nocase ascii wide
                        $string41 = /KeePwn\-main\.zip/ nocase ascii wide
                        $string42 = "Orange-Cyberdefense/KeePwn" nocase ascii wide
                        $string43 = "Orange-Cyberdefense/KeePwn" nocase ascii wide
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