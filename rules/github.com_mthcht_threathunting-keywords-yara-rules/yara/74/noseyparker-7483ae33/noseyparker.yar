rule noseyparker
{
    meta:
        description = "Detection patterns for the tool 'noseyparker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noseyparker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " github repos list --org" nocase ascii wide
                        $string2 = " github repos list --user " nocase ascii wide
                        $string3 = " scan --github-org" nocase ascii wide
                        $string4 = " scan --github-user" nocase ascii wide
                        $string5 = /\/noseyparker\.git/ nocase ascii wide
                        $string6 = "noseyparker report --datastore " nocase ascii wide
                        $string7 = "noseyparker scan --datastore " nocase ascii wide
                        $string8 = "noseyparker summarize --datastore " nocase ascii wide
                        $string9 = "noseyparker-cli" nocase ascii wide
                        $string10 = "noseyparker-main" nocase ascii wide
                        $string11 = /noseyparker\-v.{0,1000}\-universal\-macos/ nocase ascii wide
                        $string12 = /noseyparker\-v.{0,1000}\-x86_64\-unknown\-linux\-gnu/
                        $string13 = "praetorian-inc/noseyparker" nocase ascii wide

    condition:
        any of them
}