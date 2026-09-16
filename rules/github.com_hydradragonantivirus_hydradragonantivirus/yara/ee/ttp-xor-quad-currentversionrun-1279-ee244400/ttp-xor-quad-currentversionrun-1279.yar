rule TTP_XOR_QUAD_CurrentVersionRun_1279 {
  strings:
    $key_1279 = { 41 16 [2] 65 18 [2] 4e 34 [2] 60 16 [2] 74 0d [2] 7b 17 [2] 65 0a [2] 67 0b [2] 7c 0d [2] 60 0a [2] 7c 25 }

  condition:
    any of them
}