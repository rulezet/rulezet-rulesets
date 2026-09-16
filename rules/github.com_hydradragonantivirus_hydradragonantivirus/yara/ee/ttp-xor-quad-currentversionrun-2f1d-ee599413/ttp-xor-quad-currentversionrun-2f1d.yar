rule TTP_XOR_QUAD_CurrentVersionRun_2f1d {
  strings:
    $key_2f1d = { 7c 72 [2] 58 7c [2] 73 50 [2] 5d 72 [2] 49 69 [2] 46 73 [2] 58 6e [2] 5a 6f [2] 41 69 [2] 5d 6e [2] 41 41 }

  condition:
    any of them
}