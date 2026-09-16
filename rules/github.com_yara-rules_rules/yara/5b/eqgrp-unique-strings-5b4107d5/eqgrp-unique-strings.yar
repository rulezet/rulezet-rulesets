rule EQGRP_Unique_Strings 
{

    meta:
        description = "EQGRP Toolset Firewall - Unique strings"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"

    strings:
        $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
        $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"

    condition:
        1 of them
}