rule TTP_XOR_QUAD_CurrentVersionRun_3b9a {
  strings:
    $key_3b9a = { 68 f5 [2] 4c fb [2] 67 d7 [2] 49 f5 [2] 5d ee [2] 52 f4 [2] 4c e9 [2] 4e e8 [2] 55 ee [2] 49 e9 [2] 55 c6 }

  condition:
    any of them
}