rule rule_cryptomining_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cryptomining' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cryptomining"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cryptomining_offensive_tool_keyword = /\/cryptomining\.git/
                        $string2_cryptomining_offensive_tool_keyword = "/tmp/cryptomining"
                        $string3_cryptomining_offensive_tool_keyword = /\[\+\]\sCryptomining\sfolder\screated\!/
                        $string4_cryptomining_offensive_tool_keyword = "ca378ad09474b4c41b94590b65d3cdf28cd8e28063f1f9c5aa753f8f1b1ed233"
                        $string5_cryptomining_offensive_tool_keyword = "tarcisio-marinho/cryptomining"

    condition:
        any of them
}