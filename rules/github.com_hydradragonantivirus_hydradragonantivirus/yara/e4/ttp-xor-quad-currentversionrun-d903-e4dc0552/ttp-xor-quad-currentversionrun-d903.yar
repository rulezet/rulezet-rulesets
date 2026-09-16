rule TTP_XOR_QUAD_CurrentVersionRun_d903 {
  strings:
    $key_d903 = { 8a 6c [2] ae 62 [2] 85 4e [2] ab 6c [2] bf 77 [2] b0 6d [2] ae 70 [2] ac 71 [2] b7 77 [2] ab 70 [2] b7 5f }

  condition:
    any of them
}