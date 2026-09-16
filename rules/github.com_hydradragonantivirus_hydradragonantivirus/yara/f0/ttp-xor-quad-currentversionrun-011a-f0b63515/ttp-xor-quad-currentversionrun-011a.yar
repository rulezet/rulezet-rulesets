rule TTP_XOR_QUAD_CurrentVersionRun_011a {
  strings:
    $key_011a = { 52 75 [2] 76 7b [2] 5d 57 [2] 73 75 [2] 67 6e [2] 68 74 [2] 76 69 [2] 74 68 [2] 6f 6e [2] 73 69 [2] 6f 46 }

  condition:
    any of them
}