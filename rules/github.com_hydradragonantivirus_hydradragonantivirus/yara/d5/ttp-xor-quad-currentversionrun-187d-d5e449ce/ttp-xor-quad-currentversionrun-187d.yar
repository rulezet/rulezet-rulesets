rule TTP_XOR_QUAD_CurrentVersionRun_187d {
  strings:
    $key_187d = { 4b 12 [2] 6f 1c [2] 44 30 [2] 6a 12 [2] 7e 09 [2] 71 13 [2] 6f 0e [2] 6d 0f [2] 76 09 [2] 6a 0e [2] 76 21 }

  condition:
    any of them
}