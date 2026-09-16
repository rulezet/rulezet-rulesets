import "pe"
rule hmimys_Protect_v10_additional: PEiD
{
    strings:
        $a = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 }
    condition:
        $a at pe.entry_point

}