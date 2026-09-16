rule TTP_XOR_QUAD_CurrentVersionRun_325b {
  strings:
    $key_325b = { 61 34 [2] 45 3a [2] 6e 16 [2] 40 34 [2] 54 2f [2] 5b 35 [2] 45 28 [2] 47 29 [2] 5c 2f [2] 40 28 [2] 5c 07 }

  condition:
    any of them
}