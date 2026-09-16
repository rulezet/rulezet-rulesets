rule TTP_XOR_QUAD_CurrentVersionRun_20b3 {
  strings:
    $key_20b3 = { 73 dc [2] 57 d2 [2] 7c fe [2] 52 dc [2] 46 c7 [2] 49 dd [2] 57 c0 [2] 55 c1 [2] 4e c7 [2] 52 c0 [2] 4e ef }

  condition:
    any of them
}