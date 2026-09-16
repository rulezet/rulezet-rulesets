rule TTP_XOR_QUAD_CurrentVersionRun_520b {
  strings:
    $key_520b = { 01 64 [2] 25 6a [2] 0e 46 [2] 20 64 [2] 34 7f [2] 3b 65 [2] 25 78 [2] 27 79 [2] 3c 7f [2] 20 78 [2] 3c 57 }

  condition:
    any of them
}