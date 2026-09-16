rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_8b272d3350b6_4609 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash4       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1 = "k(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";}" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(func" ascii
    $s3 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return" ascii
    $s4 = "rn \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(fun" ascii
    $s5 = "})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}