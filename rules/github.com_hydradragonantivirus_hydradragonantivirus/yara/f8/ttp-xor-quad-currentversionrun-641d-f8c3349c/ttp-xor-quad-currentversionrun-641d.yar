rule TTP_XOR_QUAD_CurrentVersionRun_641d {
  strings:
    $key_641d = { 37 72 [2] 13 7c [2] 38 50 [2] 16 72 [2] 02 69 [2] 0d 73 [2] 13 6e [2] 11 6f [2] 0a 69 [2] 16 6e [2] 0a 41 }

  condition:
    any of them
}