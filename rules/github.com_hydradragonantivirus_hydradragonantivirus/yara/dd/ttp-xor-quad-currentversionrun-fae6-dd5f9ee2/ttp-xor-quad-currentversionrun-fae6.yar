rule TTP_XOR_QUAD_CurrentVersionRun_fae6 {
  strings:
    $key_fae6 = { a9 89 [2] 8d 87 [2] a6 ab [2] 88 89 [2] 9c 92 [2] 93 88 [2] 8d 95 [2] 8f 94 [2] 94 92 [2] 88 95 [2] 94 ba }

  condition:
    any of them
}