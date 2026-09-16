rule TTP_XOR_QUAD_CurrentVersionRun_efe6 {
  strings:
    $key_efe6 = { bc 89 [2] 98 87 [2] b3 ab [2] 9d 89 [2] 89 92 [2] 86 88 [2] 98 95 [2] 9a 94 [2] 81 92 [2] 9d 95 [2] 81 ba }

  condition:
    any of them
}