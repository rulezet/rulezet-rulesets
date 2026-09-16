rule TTP_XOR_QUAD_CurrentVersionRun_732b {
  strings:
    $key_732b = { 20 44 [2] 04 4a [2] 2f 66 [2] 01 44 [2] 15 5f [2] 1a 45 [2] 04 58 [2] 06 59 [2] 1d 5f [2] 01 58 [2] 1d 77 }

  condition:
    any of them
}