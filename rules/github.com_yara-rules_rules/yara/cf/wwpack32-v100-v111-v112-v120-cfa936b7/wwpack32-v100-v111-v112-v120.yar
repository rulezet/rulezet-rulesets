import "pe"
rule WWPack32_v100_v111_v112_v120: PEiD
{
    strings:
        $a = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }
    condition:
        $a at pe.entry_point

}