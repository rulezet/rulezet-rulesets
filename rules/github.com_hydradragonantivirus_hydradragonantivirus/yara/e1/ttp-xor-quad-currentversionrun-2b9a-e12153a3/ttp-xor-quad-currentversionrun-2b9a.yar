rule TTP_XOR_QUAD_CurrentVersionRun_2b9a {
  strings:
    $key_2b9a = { 78 f5 [2] 5c fb [2] 77 d7 [2] 59 f5 [2] 4d ee [2] 42 f4 [2] 5c e9 [2] 5e e8 [2] 45 ee [2] 59 e9 [2] 45 c6 }

  condition:
    any of them
}