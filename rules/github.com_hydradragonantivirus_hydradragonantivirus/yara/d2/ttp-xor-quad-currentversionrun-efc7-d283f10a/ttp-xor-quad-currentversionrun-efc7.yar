rule TTP_XOR_QUAD_CurrentVersionRun_efc7 {
  strings:
    $key_efc7 = { bc a8 [2] 98 a6 [2] b3 8a [2] 9d a8 [2] 89 b3 [2] 86 a9 [2] 98 b4 [2] 9a b5 [2] 81 b3 [2] 9d b4 [2] 81 9b }

  condition:
    any of them
}