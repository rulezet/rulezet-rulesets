import "pe"
rule CodeSafe_v20_additional: PEiD
{
    strings:
        $a = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }
    condition:
        $a at pe.entry_point

}