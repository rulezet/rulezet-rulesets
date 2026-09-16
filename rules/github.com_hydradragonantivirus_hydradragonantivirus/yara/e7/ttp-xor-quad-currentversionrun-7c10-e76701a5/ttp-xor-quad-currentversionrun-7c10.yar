rule TTP_XOR_QUAD_CurrentVersionRun_7c10 {
  strings:
    $key_7c10 = { 2f 7f [2] 0b 71 [2] 20 5d [2] 0e 7f [2] 1a 64 [2] 15 7e [2] 0b 63 [2] 09 62 [2] 12 64 [2] 0e 63 [2] 12 4c }

  condition:
    any of them
}