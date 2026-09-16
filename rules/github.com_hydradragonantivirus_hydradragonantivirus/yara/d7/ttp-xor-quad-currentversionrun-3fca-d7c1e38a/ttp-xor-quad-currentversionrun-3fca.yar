rule TTP_XOR_QUAD_CurrentVersionRun_3fca {
  strings:
    $key_3fca = { 6c a5 [2] 48 ab [2] 63 87 [2] 4d a5 [2] 59 be [2] 56 a4 [2] 48 b9 [2] 4a b8 [2] 51 be [2] 4d b9 [2] 51 96 }

  condition:
    any of them
}