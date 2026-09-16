import "pe"
rule WWPACK_v302_v302a_v304_Relocations_pack_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }
    condition:
        $a at pe.entry_point

}