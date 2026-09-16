rule TTP_XOR_QUAD_CurrentVersionRun_0f55 {
  strings:
    $key_0f55 = { 5c 3a [2] 78 34 [2] 53 18 [2] 7d 3a [2] 69 21 [2] 66 3b [2] 78 26 [2] 7a 27 [2] 61 21 [2] 7d 26 [2] 61 09 }

  condition:
    any of them
}