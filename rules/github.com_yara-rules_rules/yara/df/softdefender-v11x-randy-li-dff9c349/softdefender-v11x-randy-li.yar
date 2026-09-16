import "pe"
rule SoftDefender_V11X_Randy_Li: PEiD
{
    strings:
        $a = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }
    condition:
        $a at pe.entry_point

}