rule TTP_XOR_QUAD_CurrentVersionRun_3fd7 {
  strings:
    $key_3fd7 = { 6c b8 [2] 48 b6 [2] 63 9a [2] 4d b8 [2] 59 a3 [2] 56 b9 [2] 48 a4 [2] 4a a5 [2] 51 a3 [2] 4d a4 [2] 51 8b }

  condition:
    any of them
}