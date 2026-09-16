rule TTP_XOR_QUAD_CurrentVersionRun_1c45 {
  strings:
    $key_1c45 = { 4f 2a [2] 6b 24 [2] 40 08 [2] 6e 2a [2] 7a 31 [2] 75 2b [2] 6b 36 [2] 69 37 [2] 72 31 [2] 6e 36 [2] 72 19 }

  condition:
    any of them
}