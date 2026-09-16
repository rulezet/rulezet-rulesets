rule GraphSpy
{
    meta:
        description = "Detection patterns for the tool 'GraphSpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphSpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGraphSpy\.py/ nocase ascii wide
                        $string2 = /\/\.gspy\/databases\//
                        $string3 = /\/\.local\/bin\/graphspy/
                        $string4 = /\/GraphSpy\.git/ nocase ascii wide
                        $string5 = /\/GraphSpy\.py/ nocase ascii wide
                        $string6 = /\/opt\/gspy_log\.txt/
                        $string7 = /\/pypi\.org\/project\/GraphSpy/ nocase ascii wide
                        $string8 = /\\GraphSpy\.py/ nocase ascii wide
                        $string9 = /\]\sStarting\sGraphSpy\.\sOpen\sin\syour\sbrowser\sby\sgoing\sto\sthe\surl\sdisplayed\sbelow\./ nocase ascii wide
                        $string10 = "828411d980e653c3fa63dd031839e52ae1800b4f29f3b03f7acad492811dce2b" nocase ascii wide
                        $string11 = /app\.config\[\'graph_spy_db_folder\'\]/ nocase ascii wide
                        $string12 = /app\.config\[\'graph_spy_db_path\'\]/ nocase ascii wide
                        $string13 = "f0037d99bc3119fc613d304af20599e8c791b1c99208d5d452a01738777f7b49" nocase ascii wide
                        $string14 = "graphspy -i " nocase ascii wide
                        $string15 = /GraphSpy\.GraphSpy\:main/ nocase ascii wide
                        $string16 = /GraphSpy\-master\.zip/ nocase ascii wide
                        $string17 = "pipx install graphspy" nocase ascii wide
                        $string18 = "pipx upgrade graphspy" nocase ascii wide
                        $string19 = "RedByte1337/GraphSpy" nocase ascii wide

    condition:
        any of them
}