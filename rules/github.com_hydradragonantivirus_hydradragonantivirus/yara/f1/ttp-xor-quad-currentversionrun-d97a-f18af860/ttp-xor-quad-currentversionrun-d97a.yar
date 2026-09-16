rule TTP_XOR_QUAD_CurrentVersionRun_d97a {
  strings:
    $key_d97a = { 8a 15 [2] ae 1b [2] 85 37 [2] ab 15 [2] bf 0e [2] b0 14 [2] ae 09 [2] ac 08 [2] b7 0e [2] ab 09 [2] b7 26 }

  condition:
    any of them
}