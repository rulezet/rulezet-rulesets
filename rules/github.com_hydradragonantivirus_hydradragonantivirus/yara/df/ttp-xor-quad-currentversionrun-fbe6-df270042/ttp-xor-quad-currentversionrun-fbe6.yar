rule TTP_XOR_QUAD_CurrentVersionRun_fbe6 {
  strings:
    $key_fbe6 = { a8 89 [2] 8c 87 [2] a7 ab [2] 89 89 [2] 9d 92 [2] 92 88 [2] 8c 95 [2] 8e 94 [2] 95 92 [2] 89 95 [2] 95 ba }

  condition:
    any of them
}