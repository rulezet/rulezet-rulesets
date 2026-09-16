rule TTP_XOR_QUAD_CurrentVersionRun_317d {
  strings:
    $key_317d = { 62 12 [2] 46 1c [2] 6d 30 [2] 43 12 [2] 57 09 [2] 58 13 [2] 46 0e [2] 44 0f [2] 5f 09 [2] 43 0e [2] 5f 21 }

  condition:
    any of them
}