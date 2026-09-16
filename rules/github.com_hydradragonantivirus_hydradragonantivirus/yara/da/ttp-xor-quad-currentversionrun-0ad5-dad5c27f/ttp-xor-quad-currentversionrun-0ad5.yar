rule TTP_XOR_QUAD_CurrentVersionRun_0ad5 {
  strings:
    $key_0ad5 = { 59 ba [2] 7d b4 [2] 56 98 [2] 78 ba [2] 6c a1 [2] 63 bb [2] 7d a6 [2] 7f a7 [2] 64 a1 [2] 78 a6 [2] 64 89 }

  condition:
    any of them
}