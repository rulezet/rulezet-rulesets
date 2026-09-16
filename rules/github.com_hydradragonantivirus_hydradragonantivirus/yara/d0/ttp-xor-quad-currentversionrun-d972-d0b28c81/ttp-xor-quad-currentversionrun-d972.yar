rule TTP_XOR_QUAD_CurrentVersionRun_d972 {
  strings:
    $key_d972 = { 8a 1d [2] ae 13 [2] 85 3f [2] ab 1d [2] bf 06 [2] b0 1c [2] ae 01 [2] ac 00 [2] b7 06 [2] ab 01 [2] b7 2e }

  condition:
    any of them
}