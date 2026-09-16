import "pe"
rule ASProtect_v_If_you_know_this_version_post_on_PEiD_board_h2_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }
    condition:
        $a at pe.entry_point

}