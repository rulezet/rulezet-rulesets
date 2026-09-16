import "pe"
rule GCC_CYGWIN_MSYS_sign_ASL: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 08 A1 00 ?? ?? 00 85 C0 74 01 CC D9 7D FE 0F B7 4D FE 81 E1 C0 F0 FF FF 66 89 4D FE 0F B7 55 FE 81 CA 3F 03 00 00 66 89 55 FE D9 6D FE }
    condition:
        $a at pe.entry_point

}