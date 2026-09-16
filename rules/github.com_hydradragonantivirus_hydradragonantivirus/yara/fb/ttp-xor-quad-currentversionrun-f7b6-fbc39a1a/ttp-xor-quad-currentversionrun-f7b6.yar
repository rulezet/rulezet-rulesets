rule TTP_XOR_QUAD_CurrentVersionRun_f7b6 {
  strings:
    $key_f7b6 = { a4 d9 [2] 80 d7 [2] ab fb [2] 85 d9 [2] 91 c2 [2] 9e d8 [2] 80 c5 [2] 82 c4 [2] 99 c2 [2] 85 c5 [2] 99 ea }

  condition:
    any of them
}