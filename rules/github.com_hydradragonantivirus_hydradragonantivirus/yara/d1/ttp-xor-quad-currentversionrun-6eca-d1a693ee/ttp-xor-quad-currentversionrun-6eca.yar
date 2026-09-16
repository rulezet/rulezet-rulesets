rule TTP_XOR_QUAD_CurrentVersionRun_6eca {
  strings:
    $key_6eca = { 3d a5 [2] 19 ab [2] 32 87 [2] 1c a5 [2] 08 be [2] 07 a4 [2] 19 b9 [2] 1b b8 [2] 00 be [2] 1c b9 [2] 00 96 }

  condition:
    any of them
}