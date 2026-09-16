rule TTP_XOR_QUAD_CurrentVersionRun_047a {
  strings:
    $key_047a = { 57 15 [2] 73 1b [2] 58 37 [2] 76 15 [2] 62 0e [2] 6d 14 [2] 73 09 [2] 71 08 [2] 6a 0e [2] 76 09 [2] 6a 26 }

  condition:
    any of them
}