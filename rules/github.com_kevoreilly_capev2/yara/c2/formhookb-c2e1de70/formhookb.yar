rule FormhookB
{
    meta:
        author = "kevoreilly"
        description = "Formbook Anti-hook Bypass"
        cape_options = "clear,bp0=$entry,action0=scan,hc0=1,bp1=$new_remap,action1=setdst:ntdll,count1=0,bp2=$code+14,count=0"
        packed = "08c5f44d57f5ccc285596b3d9921bf7fbbbf7f9a827bb3285a800e4c9faf6731"
    strings:
        $decode = {B8 67 66 66 66 F7 E? C1 FA 03 8B ?2 C1 E? 1F 03 ?2}
        $entry = {55 8B EC 83 EC ?4 53 56 57 [480-520] 8B E5 5D C3}
        $new_remap = {8B (86 [2] 00 00|46 ??|06) 5F 5E 5B 8B E5 5D C3}
        $code = {8B 4E 18 50 6A 00 51 57 56 E8 9A 18 00 00 8B 55 10 8B 45 0C 8B 0F 83 C4 1C 52 50 FF D1 5F 5E 5D C3}
    condition:
        2 of them
}