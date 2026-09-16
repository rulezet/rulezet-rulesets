rule TTP_XOR_QUAD_CurrentVersionRun_1c25 {
  strings:
    $key_1c25 = { 4f 4a [2] 6b 44 [2] 40 68 [2] 6e 4a [2] 7a 51 [2] 75 4b [2] 6b 56 [2] 69 57 [2] 72 51 [2] 6e 56 [2] 72 79 }

  condition:
    any of them
}