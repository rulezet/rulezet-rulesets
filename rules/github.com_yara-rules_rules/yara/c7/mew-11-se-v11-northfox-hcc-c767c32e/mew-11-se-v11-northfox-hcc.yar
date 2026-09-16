import "pe"
rule MEW_11_SE_v11_Northfox_HCC: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C }
        $b = { E9 ?? ?? ?? FF 0C ?0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}