rule TTP_XOR_QUAD_CurrentVersionRun_1465 {
  strings:
    $key_1465 = { 47 0a [2] 63 04 [2] 48 28 [2] 66 0a [2] 72 11 [2] 7d 0b [2] 63 16 [2] 61 17 [2] 7a 11 [2] 66 16 [2] 7a 39 }

  condition:
    any of them
}