rule TTP_XOR_QUAD_CurrentVersionRun_d9fa {
  strings:
    $key_d9fa = { 8a 95 [2] ae 9b [2] 85 b7 [2] ab 95 [2] bf 8e [2] b0 94 [2] ae 89 [2] ac 88 [2] b7 8e [2] ab 89 [2] b7 a6 }

  condition:
    any of them
}