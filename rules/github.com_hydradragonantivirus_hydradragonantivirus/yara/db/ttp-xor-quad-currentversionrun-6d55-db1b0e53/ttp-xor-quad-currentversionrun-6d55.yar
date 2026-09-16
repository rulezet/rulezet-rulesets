rule TTP_XOR_QUAD_CurrentVersionRun_6d55 {
  strings:
    $key_6d55 = { 3e 3a [2] 1a 34 [2] 31 18 [2] 1f 3a [2] 0b 21 [2] 04 3b [2] 1a 26 [2] 18 27 [2] 03 21 [2] 1f 26 [2] 03 09 }

  condition:
    any of them
}