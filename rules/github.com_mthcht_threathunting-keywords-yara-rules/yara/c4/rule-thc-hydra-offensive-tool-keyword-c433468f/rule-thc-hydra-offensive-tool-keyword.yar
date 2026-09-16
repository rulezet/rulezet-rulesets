rule rule_thc_hydra_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_thc_hydra_offensive_tool_keyword = /\sdefault_logins\.txt/
                        $string2_thc_hydra_offensive_tool_keyword = " thc-hidra"
                        $string3_thc_hydra_offensive_tool_keyword = /\.\/hydra\s/
                        $string4_thc_hydra_offensive_tool_keyword = /\.\/xhydra/
                        $string5_thc_hydra_offensive_tool_keyword = "/hydra -"
                        $string6_thc_hydra_offensive_tool_keyword = "/thc-hydra/"
                        $string7_thc_hydra_offensive_tool_keyword = /common_passwords\.txt/
                        $string8_thc_hydra_offensive_tool_keyword = "dpl4hydra "
                        $string9_thc_hydra_offensive_tool_keyword = /dpl4hydra\.sh/
                        $string10_thc_hydra_offensive_tool_keyword = /dpl4hydra_.{0,100}\.csv/
                        $string11_thc_hydra_offensive_tool_keyword = /dpl4hydra_.{0,100}\.tmp/
                        $string12_thc_hydra_offensive_tool_keyword = "dpl4hydra_linksys"
                        $string13_thc_hydra_offensive_tool_keyword = /hydra\s.{0,100}\sftp\:\/\//
                        $string14_thc_hydra_offensive_tool_keyword = /hydra\s.{0,100}\shttp\-post\-form\s/
                        $string15_thc_hydra_offensive_tool_keyword = /hydra\s.{0,100}\smysql\:\/\//
                        $string16_thc_hydra_offensive_tool_keyword = /hydra\s.{0,100}\sssh\:\/\//
                        $string17_thc_hydra_offensive_tool_keyword = /hydra\s.{0,100}\stelnet\:\/\//
                        $string18_thc_hydra_offensive_tool_keyword = "hydra smtp-enum"
                        $string19_thc_hydra_offensive_tool_keyword = "hydra:x:10001:"
                        $string20_thc_hydra_offensive_tool_keyword = "HYDRA_PROXY_HTTP"
                        $string21_thc_hydra_offensive_tool_keyword = "hydra-cobaltstrike"
                        $string22_thc_hydra_offensive_tool_keyword = "install hydra-gtk"
                        $string23_thc_hydra_offensive_tool_keyword = "pw-inspector -"
                        $string24_thc_hydra_offensive_tool_keyword = /pw\-inspector\./
                        $string25_thc_hydra_offensive_tool_keyword = "thc-hydra"
                        $string26_thc_hydra_offensive_tool_keyword = /thc\-hydra\.git/
                        $string27_thc_hydra_offensive_tool_keyword = /thc\-hydra\.git/
                        $string28_thc_hydra_offensive_tool_keyword = "vanhauser-thc/thc-hydra"
                        $string29_thc_hydra_offensive_tool_keyword = "hydra -"
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