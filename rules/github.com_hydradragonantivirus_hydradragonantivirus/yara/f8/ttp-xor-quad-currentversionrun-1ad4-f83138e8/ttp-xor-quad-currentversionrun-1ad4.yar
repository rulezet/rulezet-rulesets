rule TTP_XOR_QUAD_CurrentVersionRun_1ad4 {
  strings:
    $key_1ad4 = { 49 bb [2] 6d b5 [2] 46 99 [2] 68 bb [2] 7c a0 [2] 73 ba [2] 6d a7 [2] 6f a6 [2] 74 a0 [2] 68 a7 [2] 74 88 }

  condition:
    any of them
}