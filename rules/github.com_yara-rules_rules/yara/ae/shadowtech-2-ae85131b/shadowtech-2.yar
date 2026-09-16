rule ShadowTech_2
{
    meta:
        description = "ShadowTech RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /\#(S)trings/
        $string2 = /\#(G)UID/
        $string3 = /\#(B)lob/
        $string4 = /(S)hadowTech Rat\.exe/
        $string5 = /(S)hadowTech_Rat/

    condition:
        all of them
}