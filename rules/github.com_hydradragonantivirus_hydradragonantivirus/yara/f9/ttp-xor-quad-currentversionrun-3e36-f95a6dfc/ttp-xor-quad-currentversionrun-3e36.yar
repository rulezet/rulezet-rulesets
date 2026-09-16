rule TTP_XOR_QUAD_CurrentVersionRun_3e36 {
  strings:
    $key_3e36 = { 6d 59 [2] 49 57 [2] 62 7b [2] 4c 59 [2] 58 42 [2] 57 58 [2] 49 45 [2] 4b 44 [2] 50 42 [2] 4c 45 [2] 50 6a }

  condition:
    any of them
}