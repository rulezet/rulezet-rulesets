import "pe"
rule PE_Password_v02_SMTSMF_SMT: PEiD
{
    strings:
        $a = { E8 04 00 00 00 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 00 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }
    condition:
        $a at pe.entry_point

}