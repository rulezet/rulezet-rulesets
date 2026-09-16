rule TTP_XOR_QUAD_CurrentVersionRun_d960 {
  strings:
    $key_d960 = { 8a 0f [2] ae 01 [2] 85 2d [2] ab 0f [2] bf 14 [2] b0 0e [2] ae 13 [2] ac 12 [2] b7 14 [2] ab 13 [2] b7 3c }

  condition:
    any of them
}