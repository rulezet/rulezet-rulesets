rule TTP_XOR_QUAD_CurrentVersionRun_3e78 {
  strings:
    $key_3e78 = { 6d 17 [2] 49 19 [2] 62 35 [2] 4c 17 [2] 58 0c [2] 57 16 [2] 49 0b [2] 4b 0a [2] 50 0c [2] 4c 0b [2] 50 24 }

  condition:
    any of them
}