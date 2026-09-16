import "pe"
rule Comt_010d_original: PEiD
{
    strings:
        $a = { 45 4E 43 2E 43 4F 4D 2E 42 26 46 3D 0D 0A 25 30 30 25 40 40 50 5A 2D 72 6D 2D 72 6D 2D 4C 23 50 5F 52 5E 4E 31 35 52 58 2D 71 6E 2D 71 6E 50 2D 40 21 50 59 2D 21 70 2D 21 60 2D 21 30 50 5D 3D 0D 0A 58 2D 62 21 50 5F 57 52 5E 21 35 47 47 21 }
    condition:
        $a at pe.entry_point

}