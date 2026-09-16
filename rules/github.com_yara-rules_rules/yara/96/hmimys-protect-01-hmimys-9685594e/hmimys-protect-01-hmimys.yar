import "pe"
rule hmimys_protect_01_hmimys: PEiD
{
    strings:
        $a = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 }
    condition:
        $a at pe.entry_point

}