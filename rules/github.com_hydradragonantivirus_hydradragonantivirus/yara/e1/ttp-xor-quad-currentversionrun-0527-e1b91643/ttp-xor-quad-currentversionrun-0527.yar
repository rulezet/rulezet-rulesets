rule TTP_XOR_QUAD_CurrentVersionRun_0527 {
  strings:
    $key_0527 = { 56 48 [2] 72 46 [2] 59 6a [2] 77 48 [2] 63 53 [2] 6c 49 [2] 72 54 [2] 70 55 [2] 6b 53 [2] 77 54 [2] 6b 7b }

  condition:
    any of them
}