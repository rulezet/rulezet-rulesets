rule TTP_XOR_QUAD_CurrentVersionRun_522b {
  strings:
    $key_522b = { 01 44 [2] 25 4a [2] 0e 66 [2] 20 44 [2] 34 5f [2] 3b 45 [2] 25 58 [2] 27 59 [2] 3c 5f [2] 20 58 [2] 3c 77 }

  condition:
    any of them
}