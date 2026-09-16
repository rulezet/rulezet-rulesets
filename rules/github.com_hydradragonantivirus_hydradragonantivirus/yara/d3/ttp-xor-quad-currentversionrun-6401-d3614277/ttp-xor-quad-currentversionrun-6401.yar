rule TTP_XOR_QUAD_CurrentVersionRun_6401 {
  strings:
    $key_6401 = { 37 6e [2] 13 60 [2] 38 4c [2] 16 6e [2] 02 75 [2] 0d 6f [2] 13 72 [2] 11 73 [2] 0a 75 [2] 16 72 [2] 0a 5d }

  condition:
    any of them
}