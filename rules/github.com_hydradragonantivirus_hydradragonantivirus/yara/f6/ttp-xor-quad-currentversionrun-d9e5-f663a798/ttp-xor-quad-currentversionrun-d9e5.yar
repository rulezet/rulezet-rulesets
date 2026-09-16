rule TTP_XOR_QUAD_CurrentVersionRun_d9e5 {
  strings:
    $key_d9e5 = { 8a 8a [2] ae 84 [2] 85 a8 [2] ab 8a [2] bf 91 [2] b0 8b [2] ae 96 [2] ac 97 [2] b7 91 [2] ab 96 [2] b7 b9 }

  condition:
    any of them
}