rule python
{
    meta:
        description = "Detection patterns for the tool 'python' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "python"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\,exec\(__import__\(\'base64\'\)\.b64decode\(\\"/ nocase ascii wide
                        $string2 = /\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/bash/
                        $string3 = /\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/sh/
                        $string4 = /\s\-c\s\'import\spty\;pty\.spawn\(\\\\"\/bin\/sh/
                        $string5 = /python\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/bash\\"\)/

    condition:
        any of them
}