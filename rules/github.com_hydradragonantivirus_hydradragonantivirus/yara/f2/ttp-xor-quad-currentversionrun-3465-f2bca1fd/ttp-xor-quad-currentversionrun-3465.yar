rule TTP_XOR_QUAD_CurrentVersionRun_3465 {
  strings:
    $key_3465 = { 67 0a [2] 43 04 [2] 68 28 [2] 46 0a [2] 52 11 [2] 5d 0b [2] 43 16 [2] 41 17 [2] 5a 11 [2] 46 16 [2] 5a 39 }

  condition:
    any of them
}