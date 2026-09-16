rule rule_NixImports_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NixImports' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NixImports"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NixImports_offensive_tool_keyword = /\/HInvoke\.cs/ nocase ascii wide
                        $string2_NixImports_offensive_tool_keyword = /\\Loader\\Loader\.csproj/ nocase ascii wide
                        $string3_NixImports_offensive_tool_keyword = "dr4k0nia/NixImports" nocase ascii wide
                        $string4_NixImports_offensive_tool_keyword = /HInvokeHashGen\.cs/ nocase ascii wide
                        $string5_NixImports_offensive_tool_keyword = /methodHash.{0,1000}528465795/ nocase ascii wide
                        $string6_NixImports_offensive_tool_keyword = "NixImports by dr4k0nia" nocase ascii wide
                        $string7_NixImports_offensive_tool_keyword = /NixImports\.csproj/ nocase ascii wide
                        $string8_NixImports_offensive_tool_keyword = /NixImports\.exe/ nocase ascii wide
                        $string9_NixImports_offensive_tool_keyword = /NixImports\.git/ nocase ascii wide
                        $string10_NixImports_offensive_tool_keyword = /NixImports\.sln/ nocase ascii wide
                        $string11_NixImports_offensive_tool_keyword = "using NixImports" nocase ascii wide

    condition:
        any of them
}