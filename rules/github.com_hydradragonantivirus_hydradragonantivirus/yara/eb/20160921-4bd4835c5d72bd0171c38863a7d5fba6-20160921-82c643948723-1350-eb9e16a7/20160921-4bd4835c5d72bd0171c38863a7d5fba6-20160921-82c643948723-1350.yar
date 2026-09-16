rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_82c643948723_1350 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash3       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1  = "fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"O" ascii
    $s2  = "ion fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii
    $s3  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){retu" ascii
    $s4  = "k(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs\";}" ascii
    $s5  = " \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s6  = "k(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";" ascii
    $s7  = "{return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s8  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fu" ascii
    $s9  = ",(function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){" ascii
    $s10 = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){ret" ascii
    $s11 = "uck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug" ascii
    $s12 = ",(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){" ascii
    $s13 = "h\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s14 = "fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb" ascii
    $s15 = "rn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}