rule TTP_XOR_QUAD_CurrentVersionRun_f186 {
  strings:
    $key_f186 = { a2 e9 [2] 86 e7 [2] ad cb [2] 83 e9 [2] 97 f2 [2] 98 e8 [2] 86 f5 [2] 84 f4 [2] 9f f2 [2] 83 f5 [2] 9f da }

  condition:
    any of them
}