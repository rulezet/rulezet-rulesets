rule TTP_XOR_QUAD_CurrentVersionRun_ebd7 {
  strings:
    $key_ebd7 = { b8 b8 [2] 9c b6 [2] b7 9a [2] 99 b8 [2] 8d a3 [2] 82 b9 [2] 9c a4 [2] 9e a5 [2] 85 a3 [2] 99 a4 [2] 85 8b }

  condition:
    any of them
}