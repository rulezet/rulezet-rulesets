rule ADCSCoercePotato
{
    meta:
        description = "Detection patterns for the tool 'ADCSCoercePotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSCoercePotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.asp\s\-\-adcs\s\-\-template\sMachine\s\-smb2support/ nocase ascii wide
                        $string2 = /\/ADCSCoercePotato\.git/ nocase ascii wide
                        $string3 = "/ADCSCoercePotato/" nocase ascii wide
                        $string4 = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
                        $string5 = /\[\+\]\sGot\sNTLM\stype\s3\sAUTH\smessage\sfrom\s.{0,1000}\swith\shostname\s/ nocase ascii wide
                        $string6 = /\\ADCSCoercePotato\\/ nocase ascii wide
                        $string7 = /\\MSFRottenPotato\.h/ nocase ascii wide
                        $string8 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
                        $string9 = /ADCSCoercePotato\.cpp/ nocase ascii wide
                        $string10 = /ADCSCoercePotato\.exe/ nocase ascii wide
                        $string11 = /ADCSCoercePotato\.sln/ nocase ascii wide
                        $string12 = /ADCSCoercePotato\.vcxproj/ nocase ascii wide
                        $string13 = /ADCSCoercePotato\\n\-\s\@decoder_it\s2024\\/ nocase ascii wide
                        $string14 = "decoder-it/ADCSCoercePotato" nocase ascii wide
                        $string15 = /include\s\\"MSFRottenPotato\.h\\"/ nocase ascii wide
                        $string16 = "int PotatoAPI::findNTLMBytes" nocase ascii wide

    condition:
        any of them
}