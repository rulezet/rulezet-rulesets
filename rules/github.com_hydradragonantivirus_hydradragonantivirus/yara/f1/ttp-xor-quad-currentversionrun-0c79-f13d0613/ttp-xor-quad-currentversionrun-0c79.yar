rule TTP_XOR_QUAD_CurrentVersionRun_0c79 {
  strings:
    $key_0c79 = { 5f 16 [2] 7b 18 [2] 50 34 [2] 7e 16 [2] 6a 0d [2] 65 17 [2] 7b 0a [2] 79 0b [2] 62 0d [2] 7e 0a [2] 62 25 }

  condition:
    any of them
}