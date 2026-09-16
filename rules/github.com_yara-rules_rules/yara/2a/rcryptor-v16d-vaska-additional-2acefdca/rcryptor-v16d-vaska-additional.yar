import "pe"
rule RCryptor_v16d_Vaska_additional: PEiD
{
    strings:
        $a = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
    condition:
        $a at pe.entry_point

}