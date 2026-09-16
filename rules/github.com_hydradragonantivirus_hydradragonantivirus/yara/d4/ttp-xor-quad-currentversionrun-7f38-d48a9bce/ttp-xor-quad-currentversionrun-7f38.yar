rule TTP_XOR_QUAD_CurrentVersionRun_7f38 {
  strings:
    $key_7f38 = { 2c 57 [2] 08 59 [2] 23 75 [2] 0d 57 [2] 19 4c [2] 16 56 [2] 08 4b [2] 0a 4a [2] 11 4c [2] 0d 4b [2] 11 64 }

  condition:
    any of them
}