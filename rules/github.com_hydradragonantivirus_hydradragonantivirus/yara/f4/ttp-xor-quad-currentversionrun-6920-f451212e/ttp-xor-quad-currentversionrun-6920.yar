rule TTP_XOR_QUAD_CurrentVersionRun_6920 {
  strings:
    $key_6920 = { 3a 4f [2] 1e 41 [2] 35 6d [2] 1b 4f [2] 0f 54 [2] 00 4e [2] 1e 53 [2] 1c 52 [2] 07 54 [2] 1b 53 [2] 07 7c }

  condition:
    any of them
}