rule TTP_XOR_QUAD_CurrentVersionRun_7238 {
  strings:
    $key_7238 = { 21 57 [2] 05 59 [2] 2e 75 [2] 00 57 [2] 14 4c [2] 1b 56 [2] 05 4b [2] 07 4a [2] 1c 4c [2] 00 4b [2] 1c 64 }

  condition:
    any of them
}