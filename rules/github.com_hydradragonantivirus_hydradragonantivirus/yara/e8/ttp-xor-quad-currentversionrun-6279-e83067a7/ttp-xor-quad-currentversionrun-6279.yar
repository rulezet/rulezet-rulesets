rule TTP_XOR_QUAD_CurrentVersionRun_6279 {
  strings:
    $key_6279 = { 31 16 [2] 15 18 [2] 3e 34 [2] 10 16 [2] 04 0d [2] 0b 17 [2] 15 0a [2] 17 0b [2] 0c 0d [2] 10 0a [2] 0c 25 }

  condition:
    any of them
}