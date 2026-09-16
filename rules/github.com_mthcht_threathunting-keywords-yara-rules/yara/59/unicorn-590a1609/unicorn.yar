rule unicorn
{
    meta:
        description = "Detection patterns for the tool 'unicorn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unicorn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sunicorn\.py/ nocase ascii wide
                        $string2 = /\.py\s.{0,1000}\.cs\scs\sms/ nocase ascii wide
                        $string3 = /\.txt\sshellcode\shta/ nocase ascii wide
                        $string4 = /\.txt\sshellcode\smacro/ nocase ascii wide
                        $string5 = /\.txt\sshellcode\sms/ nocase ascii wide
                        $string6 = /\/unicorn\.git/ nocase ascii wide
                        $string7 = /\/unicorn\.py/ nocase ascii wide
                        $string8 = /ASBBypass\.ps1/ nocase ascii wide
                        $string9 = "trustedsec/unicorn" nocase ascii wide
                        $string10 = /unicorn\.py\s/ nocase ascii wide
                        $string11 = /unicorn\-master\.zip/ nocase ascii wide

    condition:
        any of them
}