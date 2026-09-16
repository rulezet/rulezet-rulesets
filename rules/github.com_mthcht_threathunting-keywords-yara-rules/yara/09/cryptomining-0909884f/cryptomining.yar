rule cryptomining
{
    meta:
        description = "Detection patterns for the tool 'cryptomining' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cryptomining"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/cryptomining\.git/
                        $string2 = "/tmp/cryptomining"
                        $string3 = /\[\+\]\sCryptomining\sfolder\screated\!/
                        $string4 = "ca378ad09474b4c41b94590b65d3cdf28cd8e28063f1f9c5aa753f8f1b1ed233"
                        $string5 = "tarcisio-marinho/cryptomining"

    condition:
        any of them
}