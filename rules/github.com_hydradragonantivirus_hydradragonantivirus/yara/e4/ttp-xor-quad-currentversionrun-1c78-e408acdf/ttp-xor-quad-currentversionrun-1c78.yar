rule TTP_XOR_QUAD_CurrentVersionRun_1c78 {
  strings:
    $key_1c78 = { 4f 17 [2] 6b 19 [2] 40 35 [2] 6e 17 [2] 7a 0c [2] 75 16 [2] 6b 0b [2] 69 0a [2] 72 0c [2] 6e 0b [2] 72 24 }

  condition:
    any of them
}