rule TTP_XOR_QUAD_CurrentVersionRun_651d {
  strings:
    $key_651d = { 36 72 [2] 12 7c [2] 39 50 [2] 17 72 [2] 03 69 [2] 0c 73 [2] 12 6e [2] 10 6f [2] 0b 69 [2] 17 6e [2] 0b 41 }

  condition:
    any of them
}