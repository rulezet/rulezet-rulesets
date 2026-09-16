rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_e8d738510e4d_4831 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})(),(function fuc" ascii
    $s2 = "fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo" ascii
    $s3 = " fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"OP" ascii
    $s4 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s5 = "n fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}