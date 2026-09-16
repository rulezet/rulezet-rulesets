rule TTP_XOR_QUAD_CurrentVersionRun_3937 {
  strings:
    $key_3937 = { 6a 58 [2] 4e 56 [2] 65 7a [2] 4b 58 [2] 5f 43 [2] 50 59 [2] 4e 44 [2] 4c 45 [2] 57 43 [2] 4b 44 [2] 57 6b }

  condition:
    any of them
}