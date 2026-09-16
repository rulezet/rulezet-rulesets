rule TTP_XOR_QUAD_CurrentVersionRun_7e79 {
  strings:
    $key_7e79 = { 2d 16 [2] 09 18 [2] 22 34 [2] 0c 16 [2] 18 0d [2] 17 17 [2] 09 0a [2] 0b 0b [2] 10 0d [2] 0c 0a [2] 10 25 }

  condition:
    any of them
}