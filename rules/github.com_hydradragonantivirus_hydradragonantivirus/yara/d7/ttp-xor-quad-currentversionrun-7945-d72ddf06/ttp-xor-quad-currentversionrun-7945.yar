rule TTP_XOR_QUAD_CurrentVersionRun_7945 {
  strings:
    $key_7945 = { 2a 2a [2] 0e 24 [2] 25 08 [2] 0b 2a [2] 1f 31 [2] 10 2b [2] 0e 36 [2] 0c 37 [2] 17 31 [2] 0b 36 [2] 17 19 }

  condition:
    any of them
}