rule TTP_XOR_QUAD_CurrentVersionRun_3e1b {
  strings:
    $key_3e1b = { 6d 74 [2] 49 7a [2] 62 56 [2] 4c 74 [2] 58 6f [2] 57 75 [2] 49 68 [2] 4b 69 [2] 50 6f [2] 4c 68 [2] 50 47 }

  condition:
    any of them
}