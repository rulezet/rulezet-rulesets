rule TTP_XOR_QUAD_CurrentVersionRun_d9e4 {
  strings:
    $key_d9e4 = { 8a 8b [2] ae 85 [2] 85 a9 [2] ab 8b [2] bf 90 [2] b0 8a [2] ae 97 [2] ac 96 [2] b7 90 [2] ab 97 [2] b7 b8 }

  condition:
    any of them
}