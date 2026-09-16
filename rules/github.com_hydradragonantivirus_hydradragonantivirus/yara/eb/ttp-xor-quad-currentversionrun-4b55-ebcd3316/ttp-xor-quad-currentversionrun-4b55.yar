rule TTP_XOR_QUAD_CurrentVersionRun_4b55 {
  strings:
    $key_4b55 = { 18 3a [2] 3c 34 [2] 17 18 [2] 39 3a [2] 2d 21 [2] 22 3b [2] 3c 26 [2] 3e 27 [2] 25 21 [2] 39 26 [2] 25 09 }

  condition:
    any of them
}