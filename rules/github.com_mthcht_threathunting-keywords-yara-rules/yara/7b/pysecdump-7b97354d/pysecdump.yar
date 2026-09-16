rule pysecdump
{
    meta:
        description = "Detection patterns for the tool 'pysecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysecdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/pysecdump\.git/ nocase ascii wide
                        $string2 = /\[E\]\sUnable\sto\sread\sLSA\ssecrets\.\s\sPerhaps\syou\sare\snot\sSYTEM\?/ nocase ascii wide
                        $string3 = /\\pysecdump\-master/ nocase ascii wide
                        $string4 = "342d4b1d90f163fdbce23c4bffe2fdeecb420df0472cb44a272c2a4f604f8758" nocase ascii wide
                        $string5 = "757c6b973f06e169ec2346c818f211559a084fd2adaed2e0e9e232541b62b557" nocase ascii wide
                        $string6 = "7cabf5918c2f097e102d28085a8171e98832c150aa10ddbcd1d05e8030f184ef" nocase ascii wide
                        $string7 = "a4058df23cf217a43482e2f6fa20e55ef9005d20713a6860a4974da0fe731e64" nocase ascii wide
                        $string8 = "ad7136daff93312ebb41fe388da46d2814ab6504e23b3c90b2a56a0426a558e3" nocase ascii wide
                        $string9 = /domcachedumplive\.py/ nocase ascii wide
                        $string10 = "Dump Credential Manager for all logged in users" nocase ascii wide
                        $string11 = /framework\.win32\.domcachedumplive/ nocase ascii wide
                        $string12 = /framework\.win32\.lsasecretslive/ nocase ascii wide
                        $string13 = /lsasecretslive\.py/ nocase ascii wide
                        $string14 = "pentestmonkey/pysecdump" nocase ascii wide
                        $string15 = "pysecdump -" nocase ascii wide
                        $string16 = "pysecdump v%s " nocase ascii wide
                        $string17 = /pysecdump\.exe/ nocase ascii wide
                        $string18 = /pysecdump\.py/ nocase ascii wide
                        $string19 = "pysecdump: Starting shell" nocase ascii wide
                        $string20 = "spysecdump" nocase ascii wide

    condition:
        any of them
}