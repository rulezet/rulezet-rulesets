rule TTP_XOR_QUAD_CurrentVersionRun_4964 {
  strings:
    $key_4964 = { 1a 0b [2] 3e 05 [2] 15 29 [2] 3b 0b [2] 2f 10 [2] 20 0a [2] 3e 17 [2] 3c 16 [2] 27 10 [2] 3b 17 [2] 27 38 }

  condition:
    any of them
}