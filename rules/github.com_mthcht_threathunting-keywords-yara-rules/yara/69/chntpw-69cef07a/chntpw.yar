rule chntpw
{
    meta:
        description = "Detection patterns for the tool 'chntpw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chntpw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install chntpw" nocase ascii wide
                        $string2 = /\ssam_reset_all_pw\(/ nocase ascii wide
                        $string3 = "/chntpw -"
                        $string4 = "/chntpw-140201" nocase ascii wide
                        $string5 = "/sampasswd"
                        $string6 = /\/samusrgrp\./
                        $string7 = "/sbin/chntpw"
                        $string8 = "/sbin/sampasswd"
                        $string9 = "/sbin/samunlock"
                        $string10 = "/sbin/samusrgrp"
                        $string11 = /\/usb140201\.zip/ nocase ascii wide
                        $string12 = "/usr/share/doc/chntpw"
                        $string13 = /\\chntpw\.c/ nocase ascii wide
                        $string14 = /\\chntpw\-140201/ nocase ascii wide
                        $string15 = /\\sampasswd\./ nocase ascii wide
                        $string16 = "> chntpw Main Interactive Menu <" nocase ascii wide
                        $string17 = "---------------------> SYSKEY CHECK <-----------------------" nocase ascii wide
                        $string18 = "0bb60287c127bcef5b7018b3b692eb7a91dab1a034fa65780b5e14333a63f62b" nocase ascii wide
                        $string19 = "1083596da1857862551870eb6fd06c26bdd2cac7698b27034f6cc8d773a3664b" nocase ascii wide
                        $string20 = "2acfc293585568970aa8ea676822e0c905d4eec4c0f8c743f58ce1b099dbe29d" nocase ascii wide
                        $string21 = "555009ba8f9b57011fef7ca143c78e15d11bce2e471f6b742cbddda5c2d12e60" nocase ascii wide
                        $string22 = "c88d86aee55b31827ab4782d05bd44922276955909c43c69f0fb15377cc64374" nocase ascii wide
                        $string23 = "c9598fe89c9f4ca470ce47b556fea6289b05b1850c629c2c2f51f2efc995247c" nocase ascii wide
                        $string24 = "chntpw Edit User Info & Passwords" nocase ascii wide
                        $string25 = /chntpw\.com\/download/ nocase ascii wide
                        $string26 = /chntpw\.static/ nocase ascii wide
                        $string27 = /Failed\slogins\sbefore\slockout\sis\:\s.{0,100}max_sam_lock/ nocase ascii wide
                        $string28 = /LANMAN\spassword\sIS\showever\sset\.\sWill\snow\sinstall\snew\spassword\sas\sNT\spass\sinstead/ nocase ascii wide
                        $string29 = /pkgs\.org\/download\/chntpw/ nocase ascii wide
                        $string30 = /pogostick\.net\/\~pnh\/ntpasswd\// nocase ascii wide
                        $string31 = "sampasswd -" nocase ascii wide
                        $string32 = "samunlock -" nocase ascii wide
                        $string33 = "samusrgrp -a " nocase ascii wide
                        $string34 = "samusrgrp -r " nocase ascii wide
                        $string35 = /SYSKEY\sRESET\!\\nNow\splease\sset\snew\sadministrator\spassword\!/ nocase ascii wide
                        $string36 = /Will\sadd\sthe\suser\sto\sthe\sadministrator\sgroup\s\(0x220\)/ nocase ascii wide
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