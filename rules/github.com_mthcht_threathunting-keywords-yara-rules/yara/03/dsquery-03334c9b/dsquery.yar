rule dsquery
{
    meta:
        description = "Detection patterns for the tool 'dsquery' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsquery"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /dsquery\s.{0,1000}\s\-filter\s.{0,1000}\(objectClass\=trustedDomain\).{0,1000}\s\-attr\s/ nocase ascii wide
                        $string2 = /\-filter\s.{0,1000}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=32/ nocase ascii wide
                        $string3 = /\-filter\s.{0,1000}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304/ nocase ascii wide
                        $string4 = /\-filter\s.{0,1000}\(\&\(objectClass\=User\)\(msDS\-AllowedToDelegateTo\=/ nocase ascii wide
                        $string5 = /\-filter\s.{0,1000}\(\&\(objectClass\=user\)\(servicePrincipalName\=.{0,1000}\)\(\!\(cn\=krbtgt\)\)\(\!\(samaccounttype\=805306369/ nocase ascii wide
                        $string6 = /\-filter\s.{0,1000}\(\&\(objectClass\=User\)\(serviceprincipalname\=.{0,1000}\)\(samaccountname\=.{0,1000}\s\-limit\s0\s\-attr\ssamaccountname\sserviceprincipalname/ nocase ascii wide
                        $string7 = /\-filter\s.{0,1000}\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)/ nocase ascii wide

    condition:
        any of them
}