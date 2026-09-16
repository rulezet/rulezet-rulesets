rule rule_python_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'python' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "python"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_python_greyware_tool_keyword = /\s\,exec\(__import__\(\'base64\'\)\.b64decode\(\\"/ nocase ascii wide
                        $string2_python_greyware_tool_keyword = /\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/bash/
                        $string3_python_greyware_tool_keyword = /\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/sh/
                        $string4_python_greyware_tool_keyword = /\s\-c\s\'import\spty\;pty\.spawn\(\\\\"\/bin\/sh/
                        $string5_python_greyware_tool_keyword = /python\s\-c\s\'import\spty\;pty\.spawn\(\\"\/bin\/bash\\"\)/

    condition:
        any of them
}