rule TTP_XOR_QUAD_CurrentVersionRun_dee6 {
  strings:
    $key_dee6 = { 8d 89 [2] a9 87 [2] 82 ab [2] ac 89 [2] b8 92 [2] b7 88 [2] a9 95 [2] ab 94 [2] b0 92 [2] ac 95 [2] b0 ba }

  condition:
    any of them
}