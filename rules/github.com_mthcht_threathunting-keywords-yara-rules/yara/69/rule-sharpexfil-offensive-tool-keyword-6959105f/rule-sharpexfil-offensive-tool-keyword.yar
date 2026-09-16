rule rule_SharpExfil_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpExfil_offensive_tool_keyword = /\/SharpExfil\.git/ nocase ascii wide
                        $string2_SharpExfil_offensive_tool_keyword = /\/Upload\-OneDrive\.exe/ nocase ascii wide
                        $string3_SharpExfil_offensive_tool_keyword = /\\Upload\-OneDrive\.csproj/ nocase ascii wide
                        $string4_SharpExfil_offensive_tool_keyword = /\\Upload\-OneDrive\.exe/ nocase ascii wide
                        $string5_SharpExfil_offensive_tool_keyword = /\\Upload\-OneDrive\.sln/ nocase ascii wide
                        $string6_SharpExfil_offensive_tool_keyword = ">Upload-OneDrive<" nocase ascii wide
                        $string7_SharpExfil_offensive_tool_keyword = "1723ab71aa08741de80ab99fa08291b4066e632466c47ade2884b3739bf244b0" nocase ascii wide
                        $string8_SharpExfil_offensive_tool_keyword = "5de78ea9-73a8-4c53-9d5e-3a893e439a3a" nocase ascii wide
                        $string9_SharpExfil_offensive_tool_keyword = "adm1nPanda/SharpExfil" nocase ascii wide
                        $string10_SharpExfil_offensive_tool_keyword = "f7ff8ee96535ad845f70c8a978366b33d7934132dda00de017fa5b09fd11a55a" nocase ascii wide
                        $string11_SharpExfil_offensive_tool_keyword = /https\:\/\/graph\.microsoft\.com\/v1\.0\/drive\/root\:\/testfoldera\/\{file_name\}\:\/createUploadSession/ nocase ascii wide

    condition:
        any of them
}