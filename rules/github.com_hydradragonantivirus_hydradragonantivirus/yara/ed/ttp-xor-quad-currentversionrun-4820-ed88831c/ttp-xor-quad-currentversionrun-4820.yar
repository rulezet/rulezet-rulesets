rule TTP_XOR_QUAD_CurrentVersionRun_4820 {
  strings:
    $key_4820 = { 1b 4f [2] 3f 41 [2] 14 6d [2] 3a 4f [2] 2e 54 [2] 21 4e [2] 3f 53 [2] 3d 52 [2] 26 54 [2] 3a 53 [2] 26 7c }

  condition:
    any of them
}