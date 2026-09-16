import "pe"
rule EXECryptor_V21X_SoftCompletecom_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }
    condition:
        $a at pe.entry_point

}