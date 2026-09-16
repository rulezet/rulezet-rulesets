import "pe"
rule Vx_TrojanTelefoon_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }
    condition:
        $a at pe.entry_point

}