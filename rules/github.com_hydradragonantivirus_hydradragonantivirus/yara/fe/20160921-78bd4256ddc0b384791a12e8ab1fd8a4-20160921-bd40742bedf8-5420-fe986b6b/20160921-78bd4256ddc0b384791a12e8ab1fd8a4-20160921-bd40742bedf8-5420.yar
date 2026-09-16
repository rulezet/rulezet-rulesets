rule _20160921_78bd4256ddc0b384791a12e8ab1fd8a4_20160921_bd40742bedf8_5420 {
  meta:
    description = "datamaliciousorder - from files 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "urn \"Ot\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s2 = "\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = "fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s4 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})(" ascii
    $s5 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Av\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}