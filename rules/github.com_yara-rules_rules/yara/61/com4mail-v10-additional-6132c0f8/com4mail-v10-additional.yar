import "pe"
rule Com4mail_v10_additional: PEiD
{
    strings:
        $a = { 42 45 47 49 4E 3D 3D 3D 74 66 75 64 23 6F 66 5F 43 6F 6D 34 4D 61 69 6C 5F 66 69 6C 65 23 0D 0A }
    condition:
        $a at pe.entry_point

}