rule TTP_XOR_QUAD_CurrentVersionRun_7738 {
  strings:
    $key_7738 = { 24 57 [2] 00 59 [2] 2b 75 [2] 05 57 [2] 11 4c [2] 1e 56 [2] 00 4b [2] 02 4a [2] 19 4c [2] 05 4b [2] 19 64 }

  condition:
    any of them
}