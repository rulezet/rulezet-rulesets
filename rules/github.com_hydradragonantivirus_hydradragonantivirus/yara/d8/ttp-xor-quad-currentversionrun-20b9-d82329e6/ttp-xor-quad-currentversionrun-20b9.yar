rule TTP_XOR_QUAD_CurrentVersionRun_20b9 {
  strings:
    $key_20b9 = { 73 d6 [2] 57 d8 [2] 7c f4 [2] 52 d6 [2] 46 cd [2] 49 d7 [2] 57 ca [2] 55 cb [2] 4e cd [2] 52 ca [2] 4e e5 }

  condition:
    any of them
}