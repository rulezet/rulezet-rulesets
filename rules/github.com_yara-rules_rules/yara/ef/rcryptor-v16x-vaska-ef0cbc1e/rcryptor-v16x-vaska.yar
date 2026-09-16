import "pe"
rule RCryptor_v16x_Vaska: PEiD
{
    strings:
        $a = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}