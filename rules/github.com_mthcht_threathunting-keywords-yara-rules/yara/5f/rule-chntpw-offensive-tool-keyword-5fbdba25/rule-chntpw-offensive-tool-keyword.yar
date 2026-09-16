rule rule_chntpw_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chntpw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chntpw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chntpw_offensive_tool_keyword = " install chntpw" nocase ascii wide
                        $string2_chntpw_offensive_tool_keyword = /\ssam_reset_all_pw\(/ nocase ascii wide
                        $string3_chntpw_offensive_tool_keyword = "/chntpw -"
                        $string4_chntpw_offensive_tool_keyword = "/chntpw-140201" nocase ascii wide
                        $string5_chntpw_offensive_tool_keyword = "/sampasswd"
                        $string6_chntpw_offensive_tool_keyword = /\/samusrgrp\./
                        $string7_chntpw_offensive_tool_keyword = "/sbin/chntpw"
                        $string8_chntpw_offensive_tool_keyword = "/sbin/sampasswd"
                        $string9_chntpw_offensive_tool_keyword = "/sbin/samunlock"
                        $string10_chntpw_offensive_tool_keyword = "/sbin/samusrgrp"
                        $string11_chntpw_offensive_tool_keyword = /\/usb140201\.zip/ nocase ascii wide
                        $string12_chntpw_offensive_tool_keyword = "/usr/share/doc/chntpw"
                        $string13_chntpw_offensive_tool_keyword = /\\chntpw\.c/ nocase ascii wide
                        $string14_chntpw_offensive_tool_keyword = /\\chntpw\-140201/ nocase ascii wide
                        $string15_chntpw_offensive_tool_keyword = /\\sampasswd\./ nocase ascii wide
                        $string16_chntpw_offensive_tool_keyword = "> chntpw Main Interactive Menu <" nocase ascii wide
                        $string17_chntpw_offensive_tool_keyword = "---------------------> SYSKEY CHECK <-----------------------" nocase ascii wide
                        $string18_chntpw_offensive_tool_keyword = "0bb60287c127bcef5b7018b3b692eb7a91dab1a034fa65780b5e14333a63f62b" nocase ascii wide
                        $string19_chntpw_offensive_tool_keyword = "1083596da1857862551870eb6fd06c26bdd2cac7698b27034f6cc8d773a3664b" nocase ascii wide
                        $string20_chntpw_offensive_tool_keyword = "2acfc293585568970aa8ea676822e0c905d4eec4c0f8c743f58ce1b099dbe29d" nocase ascii wide
                        $string21_chntpw_offensive_tool_keyword = "555009ba8f9b57011fef7ca143c78e15d11bce2e471f6b742cbddda5c2d12e60" nocase ascii wide
                        $string22_chntpw_offensive_tool_keyword = "c88d86aee55b31827ab4782d05bd44922276955909c43c69f0fb15377cc64374" nocase ascii wide
                        $string23_chntpw_offensive_tool_keyword = "c9598fe89c9f4ca470ce47b556fea6289b05b1850c629c2c2f51f2efc995247c" nocase ascii wide
                        $string24_chntpw_offensive_tool_keyword = "chntpw Edit User Info & Passwords" nocase ascii wide
                        $string25_chntpw_offensive_tool_keyword = /chntpw\.com\/download/ nocase ascii wide
                        $string26_chntpw_offensive_tool_keyword = /chntpw\.static/ nocase ascii wide
                        $string27_chntpw_offensive_tool_keyword = /Failed\slogins\sbefore\slockout\sis\:\s.{0,1000}max_sam_lock/ nocase ascii wide
                        $string28_chntpw_offensive_tool_keyword = /LANMAN\spassword\sIS\showever\sset\.\sWill\snow\sinstall\snew\spassword\sas\sNT\spass\sinstead/ nocase ascii wide
                        $string29_chntpw_offensive_tool_keyword = /pkgs\.org\/download\/chntpw/ nocase ascii wide
                        $string30_chntpw_offensive_tool_keyword = /pogostick\.net\/\~pnh\/ntpasswd\// nocase ascii wide
                        $string31_chntpw_offensive_tool_keyword = "sampasswd -" nocase ascii wide
                        $string32_chntpw_offensive_tool_keyword = "samunlock -" nocase ascii wide
                        $string33_chntpw_offensive_tool_keyword = "samusrgrp -a " nocase ascii wide
                        $string34_chntpw_offensive_tool_keyword = "samusrgrp -r " nocase ascii wide
                        $string35_chntpw_offensive_tool_keyword = /SYSKEY\sRESET\!\\nNow\splease\sset\snew\sadministrator\spassword\!/ nocase ascii wide
                        $string36_chntpw_offensive_tool_keyword = /Will\sadd\sthe\suser\sto\sthe\sadministrator\sgroup\s\(0x220\)/ nocase ascii wide

    condition:
        any of them
}