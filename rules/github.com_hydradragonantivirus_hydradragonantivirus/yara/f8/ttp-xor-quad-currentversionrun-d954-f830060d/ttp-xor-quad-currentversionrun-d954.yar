rule TTP_XOR_QUAD_CurrentVersionRun_d954 {
  strings:
    $key_d954 = { 8a 3b [2] ae 35 [2] 85 19 [2] ab 3b [2] bf 20 [2] b0 3a [2] ae 27 [2] ac 26 [2] b7 20 [2] ab 27 [2] b7 08 }

  condition:
    any of them
}