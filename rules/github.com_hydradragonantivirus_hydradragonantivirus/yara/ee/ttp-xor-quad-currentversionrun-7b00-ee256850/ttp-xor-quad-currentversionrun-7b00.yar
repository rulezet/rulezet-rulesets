rule TTP_XOR_QUAD_CurrentVersionRun_7b00 {
  strings:
    $key_7b00 = { 28 6f [2] 0c 61 [2] 27 4d [2] 09 6f [2] 1d 74 [2] 12 6e [2] 0c 73 [2] 0e 72 [2] 15 74 [2] 09 73 [2] 15 5c }

  condition:
    any of them
}