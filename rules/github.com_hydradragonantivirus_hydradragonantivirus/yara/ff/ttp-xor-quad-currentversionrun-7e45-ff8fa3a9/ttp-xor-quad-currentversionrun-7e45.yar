rule TTP_XOR_QUAD_CurrentVersionRun_7e45 {
  strings:
    $key_7e45 = { 2d 2a [2] 09 24 [2] 22 08 [2] 0c 2a [2] 18 31 [2] 17 2b [2] 09 36 [2] 0b 37 [2] 10 31 [2] 0c 36 [2] 10 19 }

  condition:
    any of them
}