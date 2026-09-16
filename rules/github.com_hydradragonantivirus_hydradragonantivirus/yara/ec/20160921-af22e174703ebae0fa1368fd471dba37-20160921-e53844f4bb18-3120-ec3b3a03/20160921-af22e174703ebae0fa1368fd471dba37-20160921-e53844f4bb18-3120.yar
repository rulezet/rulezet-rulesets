rule _20160921_af22e174703ebae0fa1368fd471dba37_20160921_e53844f4bb18_3120 {
  meta:
    description = "datamaliciousorder - from files 20160921_af22e174703ebae0fa1368fd471dba37.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s2 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s3 = " fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np" ascii
    $s4 = "{return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"TTs\";})" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"SUi" ascii
    $s6 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii
    $s7 = "urn \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}