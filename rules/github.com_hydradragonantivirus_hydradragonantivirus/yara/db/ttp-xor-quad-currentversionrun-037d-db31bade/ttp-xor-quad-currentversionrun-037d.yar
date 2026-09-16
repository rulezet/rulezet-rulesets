rule TTP_XOR_QUAD_CurrentVersionRun_037d {
  strings:
    $key_037d = { 50 12 [2] 74 1c [2] 5f 30 [2] 71 12 [2] 65 09 [2] 6a 13 [2] 74 0e [2] 76 0f [2] 6d 09 [2] 71 0e [2] 6d 21 }

  condition:
    any of them
}