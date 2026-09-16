rule TTP_XOR_QUAD_CurrentVersionRun_ebe6 {
  strings:
    $key_ebe6 = { b8 89 [2] 9c 87 [2] b7 ab [2] 99 89 [2] 8d 92 [2] 82 88 [2] 9c 95 [2] 9e 94 [2] 85 92 [2] 99 95 [2] 85 ba }

  condition:
    any of them
}