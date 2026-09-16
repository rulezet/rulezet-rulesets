rule TTP_XOR_QUAD_CurrentVersionRun_1b78 {
  strings:
    $key_1b78 = { 48 17 [2] 6c 19 [2] 47 35 [2] 69 17 [2] 7d 0c [2] 72 16 [2] 6c 0b [2] 6e 0a [2] 75 0c [2] 69 0b [2] 75 24 }

  condition:
    any of them
}