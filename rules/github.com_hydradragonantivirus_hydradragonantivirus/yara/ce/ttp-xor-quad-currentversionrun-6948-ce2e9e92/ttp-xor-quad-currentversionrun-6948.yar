rule TTP_XOR_QUAD_CurrentVersionRun_6948 {
  strings:
    $key_6948 = { 3a 27 [2] 1e 29 [2] 35 05 [2] 1b 27 [2] 0f 3c [2] 00 26 [2] 1e 3b [2] 1c 3a [2] 07 3c [2] 1b 3b [2] 07 14 }

  condition:
    any of them
}