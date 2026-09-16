rule TTP_XOR_QUAD_CurrentVersionRun_7615 {
  strings:
    $key_7615 = { 25 7a [2] 01 74 [2] 2a 58 [2] 04 7a [2] 10 61 [2] 1f 7b [2] 01 66 [2] 03 67 [2] 18 61 [2] 04 66 [2] 18 49 }

  condition:
    any of them
}