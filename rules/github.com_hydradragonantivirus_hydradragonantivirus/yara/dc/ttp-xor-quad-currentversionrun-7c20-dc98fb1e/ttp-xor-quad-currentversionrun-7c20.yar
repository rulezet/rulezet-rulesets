rule TTP_XOR_QUAD_CurrentVersionRun_7c20 {
  strings:
    $key_7c20 = { 2f 4f [2] 0b 41 [2] 20 6d [2] 0e 4f [2] 1a 54 [2] 15 4e [2] 0b 53 [2] 09 52 [2] 12 54 [2] 0e 53 [2] 12 7c }

  condition:
    any of them
}