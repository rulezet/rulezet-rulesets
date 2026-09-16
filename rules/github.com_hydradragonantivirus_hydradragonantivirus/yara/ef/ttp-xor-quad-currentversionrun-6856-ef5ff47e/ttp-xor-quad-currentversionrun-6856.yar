rule TTP_XOR_QUAD_CurrentVersionRun_6856 {
  strings:
    $key_6856 = { 3b 39 [2] 1f 37 [2] 34 1b [2] 1a 39 [2] 0e 22 [2] 01 38 [2] 1f 25 [2] 1d 24 [2] 06 22 [2] 1a 25 [2] 06 0a }

  condition:
    any of them
}