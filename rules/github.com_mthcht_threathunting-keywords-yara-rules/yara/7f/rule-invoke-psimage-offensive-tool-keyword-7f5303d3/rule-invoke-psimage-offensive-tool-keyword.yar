rule rule_Invoke_PSImage_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PSImage' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PSImage"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_PSImage_offensive_tool_keyword = "b4c75048a8837dbad2a829e17a1370716cc40f9a6fd3b0f50df7f0e3f97564c1" nocase ascii wide
                        $string2_Invoke_PSImage_offensive_tool_keyword = /foreach\(\`\$x\sin\(0\.\.\$lwidth\)\)\{\`\$p\=\`\$g\.GetPixel\(\`\$x\,\`\$_\)/ nocase ascii wide
                        $string3_Invoke_PSImage_offensive_tool_keyword = "Invoke-PSImage" nocase ascii wide

    condition:
        any of them
}