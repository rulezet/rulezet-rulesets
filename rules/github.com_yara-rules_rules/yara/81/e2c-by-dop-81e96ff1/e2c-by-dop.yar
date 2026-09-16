import "pe"
rule E2C_by_DoP: PEiD
{
    strings:
        $a = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3 }
    condition:
        $a at pe.entry_point

}