import "pe"
rule HideProtect_V1016C_SoftWar_Company_SignByfly: PEiD
{
    strings:
        $a = { 90 90 90 E9 D8 }
    condition:
        $a at pe.entry_point

}