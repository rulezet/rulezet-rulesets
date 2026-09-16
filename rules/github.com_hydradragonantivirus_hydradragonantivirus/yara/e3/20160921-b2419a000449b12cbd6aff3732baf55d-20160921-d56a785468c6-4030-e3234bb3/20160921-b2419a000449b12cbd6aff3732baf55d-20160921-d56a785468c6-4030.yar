rule _20160921_b2419a000449b12cbd6aff3732baf55d_20160921_d56a785468c6_4030 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = "turn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s3 = ";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s4 = "unction fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){ret" ascii
    $s5 = "{return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})()" ascii
    $s6 = "(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}