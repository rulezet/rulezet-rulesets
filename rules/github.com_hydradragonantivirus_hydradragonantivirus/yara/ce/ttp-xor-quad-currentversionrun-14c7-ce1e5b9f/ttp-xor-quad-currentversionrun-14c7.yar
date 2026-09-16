rule TTP_XOR_QUAD_CurrentVersionRun_14c7 {
  strings:
    $key_14c7 = { 47 a8 [2] 63 a6 [2] 48 8a [2] 66 a8 [2] 72 b3 [2] 7d a9 [2] 63 b4 [2] 61 b5 [2] 7a b3 [2] 66 b4 [2] 7a 9b }

  condition:
    any of them
}