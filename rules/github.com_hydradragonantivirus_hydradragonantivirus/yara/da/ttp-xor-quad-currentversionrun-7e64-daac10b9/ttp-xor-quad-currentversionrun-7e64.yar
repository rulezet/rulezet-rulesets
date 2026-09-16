rule TTP_XOR_QUAD_CurrentVersionRun_7e64 {
  strings:
    $key_7e64 = { 2d 0b [2] 09 05 [2] 22 29 [2] 0c 0b [2] 18 10 [2] 17 0a [2] 09 17 [2] 0b 16 [2] 10 10 [2] 0c 17 [2] 10 38 }

  condition:
    any of them
}