rule TTP_XOR_QUAD_CurrentVersionRun_1265 {
  strings:
    $key_1265 = { 41 0a [2] 65 04 [2] 4e 28 [2] 60 0a [2] 74 11 [2] 7b 0b [2] 65 16 [2] 67 17 [2] 7c 11 [2] 60 16 [2] 7c 39 }

  condition:
    any of them
}