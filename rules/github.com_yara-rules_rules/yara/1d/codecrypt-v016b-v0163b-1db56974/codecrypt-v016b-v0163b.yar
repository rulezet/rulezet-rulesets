import "pe"
rule CodeCrypt_v016b_v0163b: PEiD
{
    strings:
        $a = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
    condition:
        $a at pe.entry_point

}