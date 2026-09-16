rule TTP_XOR_QUAD_CurrentVersionRun_550b {
  strings:
    $key_550b = { 06 64 [2] 22 6a [2] 09 46 [2] 27 64 [2] 33 7f [2] 3c 65 [2] 22 78 [2] 20 79 [2] 3b 7f [2] 27 78 [2] 3b 57 }

  condition:
    any of them
}