rule TTP_XOR_QUAD_CurrentVersionRun_eac6 {
  strings:
    $key_eac6 = { b9 a9 [2] 9d a7 [2] b6 8b [2] 98 a9 [2] 8c b2 [2] 83 a8 [2] 9d b5 [2] 9f b4 [2] 84 b2 [2] 98 b5 [2] 84 9a }

  condition:
    any of them
}