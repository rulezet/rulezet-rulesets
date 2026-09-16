rule TTP_XOR_QUAD_CurrentVersionRun_d95b {
  strings:
    $key_d95b = { 8a 34 [2] ae 3a [2] 85 16 [2] ab 34 [2] bf 2f [2] b0 35 [2] ae 28 [2] ac 29 [2] b7 2f [2] ab 28 [2] b7 07 }

  condition:
    any of them
}