rule TTP_XOR_QUAD_CurrentVersionRun_d940 {
  strings:
    $key_d940 = { 8a 2f [2] ae 21 [2] 85 0d [2] ab 2f [2] bf 34 [2] b0 2e [2] ae 33 [2] ac 32 [2] b7 34 [2] ab 33 [2] b7 1c }

  condition:
    any of them
}