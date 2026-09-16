rule TTP_XOR_QUAD_CurrentVersionRun_d92b {
  strings:
    $key_d92b = { 8a 44 [2] ae 4a [2] 85 66 [2] ab 44 [2] bf 5f [2] b0 45 [2] ae 58 [2] ac 59 [2] b7 5f [2] ab 58 [2] b7 77 }

  condition:
    any of them
}