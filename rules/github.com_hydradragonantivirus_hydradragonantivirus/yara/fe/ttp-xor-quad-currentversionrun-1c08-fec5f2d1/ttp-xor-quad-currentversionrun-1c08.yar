rule TTP_XOR_QUAD_CurrentVersionRun_1c08 {
  strings:
    $key_1c08 = { 4f 67 [2] 6b 69 [2] 40 45 [2] 6e 67 [2] 7a 7c [2] 75 66 [2] 6b 7b [2] 69 7a [2] 72 7c [2] 6e 7b [2] 72 54 }

  condition:
    any of them
}