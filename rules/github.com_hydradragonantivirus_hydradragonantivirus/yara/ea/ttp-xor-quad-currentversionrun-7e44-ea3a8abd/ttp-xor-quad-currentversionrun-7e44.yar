rule TTP_XOR_QUAD_CurrentVersionRun_7e44 {
  strings:
    $key_7e44 = { 2d 2b [2] 09 25 [2] 22 09 [2] 0c 2b [2] 18 30 [2] 17 2a [2] 09 37 [2] 0b 36 [2] 10 30 [2] 0c 37 [2] 10 18 }

  condition:
    any of them
}