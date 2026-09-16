rule TTP_XOR_QUAD_CurrentVersionRun_4638 {
  strings:
    $key_4638 = { 15 57 [2] 31 59 [2] 1a 75 [2] 34 57 [2] 20 4c [2] 2f 56 [2] 31 4b [2] 33 4a [2] 28 4c [2] 34 4b [2] 28 64 }

  condition:
    any of them
}