rule TTP_XOR_QUAD_CurrentVersionRun_0b08 {
  strings:
    $key_0b08 = { 58 67 [2] 7c 69 [2] 57 45 [2] 79 67 [2] 6d 7c [2] 62 66 [2] 7c 7b [2] 7e 7a [2] 65 7c [2] 79 7b [2] 65 54 }

  condition:
    any of them
}