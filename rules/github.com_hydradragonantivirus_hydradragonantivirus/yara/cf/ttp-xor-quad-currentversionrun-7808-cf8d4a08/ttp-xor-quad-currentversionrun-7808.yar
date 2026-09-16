rule TTP_XOR_QUAD_CurrentVersionRun_7808 {
  strings:
    $key_7808 = { 2b 67 [2] 0f 69 [2] 24 45 [2] 0a 67 [2] 1e 7c [2] 11 66 [2] 0f 7b [2] 0d 7a [2] 16 7c [2] 0a 7b [2] 16 54 }

  condition:
    any of them
}