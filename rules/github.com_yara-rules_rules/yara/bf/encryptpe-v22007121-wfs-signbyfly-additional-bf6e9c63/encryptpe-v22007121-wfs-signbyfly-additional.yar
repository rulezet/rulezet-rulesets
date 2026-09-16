import "pe"
rule EncryptPE_V22007121_WFS_SignByfly_additional: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 37 2E 31 32 2E 31 2C 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 57 46 53 00 00 48 6F 6D 65 50 61 67 65 3A 20 77 77 77 2E 65 6E 63 72 79 70 74 }
    condition:
        $a at pe.entry_point

}