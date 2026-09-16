rule TTP_XOR_QUAD_CurrentVersionRun_7664 {
  strings:
    $key_7664 = { 25 0b [2] 01 05 [2] 2a 29 [2] 04 0b [2] 10 10 [2] 1f 0a [2] 01 17 [2] 03 16 [2] 18 10 [2] 04 17 [2] 18 38 }

  condition:
    any of them
}