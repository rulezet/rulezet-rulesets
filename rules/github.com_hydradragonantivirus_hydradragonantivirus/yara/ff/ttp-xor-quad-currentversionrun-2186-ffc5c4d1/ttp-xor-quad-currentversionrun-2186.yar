rule TTP_XOR_QUAD_CurrentVersionRun_2186 {
  strings:
    $key_2186 = { 72 e9 [2] 56 e7 [2] 7d cb [2] 53 e9 [2] 47 f2 [2] 48 e8 [2] 56 f5 [2] 54 f4 [2] 4f f2 [2] 53 f5 [2] 4f da }

  condition:
    any of them
}