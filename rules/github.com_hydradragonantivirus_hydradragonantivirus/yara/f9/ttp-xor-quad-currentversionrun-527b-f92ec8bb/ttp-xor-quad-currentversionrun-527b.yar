rule TTP_XOR_QUAD_CurrentVersionRun_527b {
  strings:
    $key_527b = { 01 14 [2] 25 1a [2] 0e 36 [2] 20 14 [2] 34 0f [2] 3b 15 [2] 25 08 [2] 27 09 [2] 3c 0f [2] 20 08 [2] 3c 27 }

  condition:
    any of them
}