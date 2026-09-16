rule unshackle
{
    meta:
        description = "Detection patterns for the tool 'unshackle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshackle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/unshackle"
                        $string2 = /\/unshackle\.git/
                        $string3 = /\/unshackle\.modules/
                        $string4 = "Fadi002/unshackle"
                        $string5 = "unshackle --"
                        $string6 = "unshackle-main"
                        $string7 = /unshackle\-v1\.0\.iso/

    condition:
        any of them
}