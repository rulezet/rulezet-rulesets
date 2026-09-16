rule TTP_XOR_QUAD_CurrentVersionRun_2665 {
  strings:
    $key_2665 = { 75 0a [2] 51 04 [2] 7a 28 [2] 54 0a [2] 40 11 [2] 4f 0b [2] 51 16 [2] 53 17 [2] 48 11 [2] 54 16 [2] 48 39 }

  condition:
    any of them
}