rule TTP_XOR_QUAD_CurrentVersionRun_6f1d {
  strings:
    $key_6f1d = { 3c 72 [2] 18 7c [2] 33 50 [2] 1d 72 [2] 09 69 [2] 06 73 [2] 18 6e [2] 1a 6f [2] 01 69 [2] 1d 6e [2] 01 41 }

  condition:
    any of them
}