rule TTP_XOR_QUAD_CurrentVersionRun_4e78 {
  strings:
    $key_4e78 = { 1d 17 [2] 39 19 [2] 12 35 [2] 3c 17 [2] 28 0c [2] 27 16 [2] 39 0b [2] 3b 0a [2] 20 0c [2] 3c 0b [2] 20 24 }

  condition:
    any of them
}