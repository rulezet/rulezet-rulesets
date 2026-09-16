import "pe"
rule AsCrypt_v01_SToRM_needs_to_be_added_additional: PEiD
{
    strings:
        $a = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
    condition:
        $a at pe.entry_point

}