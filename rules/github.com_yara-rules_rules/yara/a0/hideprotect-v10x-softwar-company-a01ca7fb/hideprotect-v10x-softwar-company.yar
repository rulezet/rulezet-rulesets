import "pe"
rule HideProtect_V10X_SoftWar_Company: PEiD
{
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $b = { 90 90 90 E9 D8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}