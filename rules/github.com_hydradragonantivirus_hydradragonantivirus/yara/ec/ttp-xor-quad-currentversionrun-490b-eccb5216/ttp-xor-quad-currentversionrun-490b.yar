rule TTP_XOR_QUAD_CurrentVersionRun_490b {
  strings:
    $key_490b = { 1a 64 [2] 3e 6a [2] 15 46 [2] 3b 64 [2] 2f 7f [2] 20 65 [2] 3e 78 [2] 3c 79 [2] 27 7f [2] 3b 78 [2] 27 57 }

  condition:
    any of them
}