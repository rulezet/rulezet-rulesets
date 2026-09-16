rule TTP_XOR_QUAD_CurrentVersionRun_d944 {
  strings:
    $key_d944 = { 8a 2b [2] ae 25 [2] 85 09 [2] ab 2b [2] bf 30 [2] b0 2a [2] ae 37 [2] ac 36 [2] b7 30 [2] ab 37 [2] b7 18 }

  condition:
    any of them
}