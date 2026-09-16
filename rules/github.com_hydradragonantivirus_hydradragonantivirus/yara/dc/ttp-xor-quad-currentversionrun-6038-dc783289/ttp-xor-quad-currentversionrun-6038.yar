rule TTP_XOR_QUAD_CurrentVersionRun_6038 {
  strings:
    $key_6038 = { 33 57 [2] 17 59 [2] 3c 75 [2] 12 57 [2] 06 4c [2] 09 56 [2] 17 4b [2] 15 4a [2] 0e 4c [2] 12 4b [2] 0e 64 }

  condition:
    any of them
}