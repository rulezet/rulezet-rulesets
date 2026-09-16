rule FormconfB
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2_1,bp0=$c2_2,action0=string:rcx,bp1=$decoy,action1=string:rdi,bp2=$config,action2=scan,bp3=$sleep+5,action3=skip,count=0,typestring=Formbook Config"
        packed = "60571b2683e7b753a77029ebe9b5e1cb9f3fbfa8d6a43e4b7239eefd13141ae4"
    strings:
        $c2_1 = {44 0F B6 5D ?? 45 84 DB 74 ?? 48 8D 4D [1-5] 41 80 FB 2F 74 11 0F B6 41 01 48 FF C1 FF C3 44 0F B6 D8 84 C0 75}
        $c2_2 = {40 53 48 83 EC 20 48 8B DA 48 85 C9 74 28 80 39 00 74 23 48 85 D2 74 1E 48 8B D1 41 B8 04 00 00 00 48 8B CB E8}
        $decoy = {44 8D 1C 33 [0-13] 48 8D 7D [1-5] 42 C6 44 [2] 00 [0-4] 48 8B CF E8}
        $config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 F6 33 C0 4C 8B E9 4C 89 75}
        $sleep = {B9 88 13 00 00 FF D7 44 8B 9B [4] 41 81 FB 00 01 00 00 75 ?? 48 39 B3 [4] 74 ?? 8B 83 [4] 05 00 20 00 00 39 B0}
    condition:
        2 of them
}