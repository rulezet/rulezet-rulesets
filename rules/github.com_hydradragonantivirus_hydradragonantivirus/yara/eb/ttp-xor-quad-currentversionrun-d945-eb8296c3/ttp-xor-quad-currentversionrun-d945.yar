rule TTP_XOR_QUAD_CurrentVersionRun_d945 {
  strings:
    $key_d945 = { 8a 2a [2] ae 24 [2] 85 08 [2] ab 2a [2] bf 31 [2] b0 2b [2] ae 36 [2] ac 37 [2] b7 31 [2] ab 36 [2] b7 19 }

  condition:
    any of them
}