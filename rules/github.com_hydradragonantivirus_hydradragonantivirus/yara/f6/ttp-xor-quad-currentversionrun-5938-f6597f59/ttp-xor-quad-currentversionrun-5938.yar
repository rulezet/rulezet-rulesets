rule TTP_XOR_QUAD_CurrentVersionRun_5938 {
  strings:
    $key_5938 = { 0a 57 [2] 2e 59 [2] 05 75 [2] 2b 57 [2] 3f 4c [2] 30 56 [2] 2e 4b [2] 2c 4a [2] 37 4c [2] 2b 4b [2] 37 64 }

  condition:
    any of them
}