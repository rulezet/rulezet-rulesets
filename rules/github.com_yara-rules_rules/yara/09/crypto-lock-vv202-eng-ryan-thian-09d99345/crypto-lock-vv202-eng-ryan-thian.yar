import "pe"
rule Crypto_Lock_vV202_Eng_Ryan_Thian: PEiD
{
    strings:
        $a = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
    condition:
        $a at pe.entry_point

}