rule thc_hydra
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdefault_logins\.txt/
                        $string2 = " thc-hidra"
                        $string3 = /\.\/hydra\s/
                        $string4 = /\.\/xhydra/
                        $string5 = "/hydra -"
                        $string6 = "/thc-hydra/"
                        $string7 = /common_passwords\.txt/
                        $string8 = "dpl4hydra "
                        $string9 = /dpl4hydra\.sh/
                        $string10 = /dpl4hydra_.{0,100}\.csv/
                        $string11 = /dpl4hydra_.{0,100}\.tmp/
                        $string12 = "dpl4hydra_linksys"
                        $string13 = /hydra\s.{0,100}\sftp\:\/\//
                        $string14 = /hydra\s.{0,100}\shttp\-post\-form\s/
                        $string15 = /hydra\s.{0,100}\smysql\:\/\//
                        $string16 = /hydra\s.{0,100}\sssh\:\/\//
                        $string17 = /hydra\s.{0,100}\stelnet\:\/\//
                        $string18 = "hydra smtp-enum"
                        $string19 = "hydra:x:10001:"
                        $string20 = "HYDRA_PROXY_HTTP"
                        $string21 = "hydra-cobaltstrike"
                        $string22 = "install hydra-gtk"
                        $string23 = "pw-inspector -"
                        $string24 = /pw\-inspector\./
                        $string25 = "thc-hydra"
                        $string26 = /thc\-hydra\.git/
                        $string27 = /thc\-hydra\.git/
                        $string28 = "vanhauser-thc/thc-hydra"
                        $string29 = "hydra -"
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