rule TTP_XOR_QUAD_CurrentVersionRun_6ec6 {
  strings:
    $key_6ec6 = { 3d a9 [2] 19 a7 [2] 32 8b [2] 1c a9 [2] 08 b2 [2] 07 a8 [2] 19 b5 [2] 1b b4 [2] 00 b2 [2] 1c b5 [2] 00 9a }

  condition:
    any of them
}