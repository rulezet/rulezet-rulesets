rule PySQLRecon
{
    meta:
        description = "Detection patterns for the tool 'PySQLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PySQLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PySQLRecon\.git/ nocase ascii wide
                        $string2 = "/PySQLRecon/tarball" nocase ascii wide
                        $string3 = "/PySQLRecon/zipball" nocase ascii wide
                        $string4 = "2bcf6152e45cf60959f276a1e7482752895a5b17dc4d4a307a470c1a40284705" nocase ascii wide
                        $string5 = "55d72ecccc3e6bbf42653009b63e1c1e90b134714aca78dfd36ec35003bc3d76" nocase ascii wide
                        $string6 = "8213d434f255fbfba9d5432770a6b4ff85463271047384feba7176a301436634" nocase ascii wide
                        $string7 = "fde8744f64a41afea0aca93478a8e310a86dd3ac1e716bfdd6687e954ad2231e" nocase ascii wide
                        $string8 = "poetry run pysqlrecon" nocase ascii wide
                        $string9 = /pysqlrecon\.db/ nocase ascii wide
                        $string10 = /pysqlrecon\.lib/ nocase ascii wide
                        $string11 = /pysqlrecon\.logger/ nocase ascii wide
                        $string12 = "Tw1sm/PySQLRecon" nocase ascii wide

    condition:
        any of them
}