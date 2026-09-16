rule TTP_XOR_QUAD_CurrentVersionRun_187a {
  strings:
    $key_187a = { 4b 15 [2] 6f 1b [2] 44 37 [2] 6a 15 [2] 7e 0e [2] 71 14 [2] 6f 09 [2] 6d 08 [2] 76 0e [2] 6a 09 [2] 76 26 }

  condition:
    any of them
}