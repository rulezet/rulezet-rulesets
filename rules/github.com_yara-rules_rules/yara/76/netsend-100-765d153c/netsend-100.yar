import "pe"
rule Netsend_100: PEiD
{
    strings:
        $a = { 58 50 50 50 59 5A 49 51 44 5B 4C 2D 66 36 2D 67 34 31 47 44 53 58 75 27 40 2C 7E 50 5E 50 5F 4F 2C 21 28 47 55 28 47 5A 28 47 6E 75 35 2D 4E 45 54 53 45 4E 44 5F 56 31 2E 30 30 5F 4A 52 54 3D 0D 0A 43 46 46 46 52 58 2C 60 2C 60 32 24 46 3D }
    condition:
        $a at pe.entry_point

}