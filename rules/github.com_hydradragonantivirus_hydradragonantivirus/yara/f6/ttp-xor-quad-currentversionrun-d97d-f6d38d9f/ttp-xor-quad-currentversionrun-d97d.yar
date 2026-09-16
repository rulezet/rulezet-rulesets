rule TTP_XOR_QUAD_CurrentVersionRun_d97d {
  strings:
    $key_d97d = { 8a 12 [2] ae 1c [2] 85 30 [2] ab 12 [2] bf 09 [2] b0 13 [2] ae 0e [2] ac 0f [2] b7 09 [2] ab 0e [2] b7 21 }

  condition:
    any of them
}