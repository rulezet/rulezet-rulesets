rule pyobfuscate
{
    meta:
        description = "Detection patterns for the tool 'pyobfuscate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyobfuscate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\#pip\sinstall\spycryptodome\s\s\,\sIt\sworks\sonly\sv3\.11\.5\sAbove\./ nocase ascii wide
                        $string2 = /https\:\/\/pyobfuscate\.com.{0,1000}\'eval\'\:\sbytes\.fromhex\(/ nocase ascii wide
                        $string3 = /https\:\/\/pyobfuscate\.com\/pyd/ nocase ascii wide
                        $string4 = /pyobfuscate\s\=\s\(/ nocase ascii wide
                        $string5 = "why,are,you,reading,this,thing,huh=" nocase ascii wide

    condition:
        any of them
}