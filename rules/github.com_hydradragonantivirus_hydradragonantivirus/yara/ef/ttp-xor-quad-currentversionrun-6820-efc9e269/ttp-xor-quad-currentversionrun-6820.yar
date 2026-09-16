rule TTP_XOR_QUAD_CurrentVersionRun_6820 {
  strings:
    $key_6820 = { 3b 4f [2] 1f 41 [2] 34 6d [2] 1a 4f [2] 0e 54 [2] 01 4e [2] 1f 53 [2] 1d 52 [2] 06 54 [2] 1a 53 [2] 06 7c }

  condition:
    any of them
}