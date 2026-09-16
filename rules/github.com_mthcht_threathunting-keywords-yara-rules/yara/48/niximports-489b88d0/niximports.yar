rule NixImports
{
    meta:
        description = "Detection patterns for the tool 'NixImports' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NixImports"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HInvoke\.cs/ nocase ascii wide
                        $string2 = /\\Loader\\Loader\.csproj/ nocase ascii wide
                        $string3 = "dr4k0nia/NixImports" nocase ascii wide
                        $string4 = /HInvokeHashGen\.cs/ nocase ascii wide
                        $string5 = /methodHash.{0,1000}528465795/ nocase ascii wide
                        $string6 = "NixImports by dr4k0nia" nocase ascii wide
                        $string7 = /NixImports\.csproj/ nocase ascii wide
                        $string8 = /NixImports\.exe/ nocase ascii wide
                        $string9 = /NixImports\.git/ nocase ascii wide
                        $string10 = /NixImports\.sln/ nocase ascii wide
                        $string11 = "using NixImports" nocase ascii wide

    condition:
        any of them
}