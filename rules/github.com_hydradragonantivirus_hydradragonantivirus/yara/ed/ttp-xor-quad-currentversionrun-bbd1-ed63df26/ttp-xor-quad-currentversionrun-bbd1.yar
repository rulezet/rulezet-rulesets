rule TTP_XOR_QUAD_CurrentVersionRun_bbd1 {
  strings:
    $key_bbd1 = { e8 be [2] cc b0 [2] e7 9c [2] c9 be [2] dd a5 [2] d2 bf [2] cc a2 [2] ce a3 [2] d5 a5 [2] c9 a2 [2] d5 8d }

  condition:
    any of them
}