rule TTP_XOR_QUAD_CurrentVersionRun_1338 {
  strings:
    $key_1338 = { 40 57 [2] 64 59 [2] 4f 75 [2] 61 57 [2] 75 4c [2] 7a 56 [2] 64 4b [2] 66 4a [2] 7d 4c [2] 61 4b [2] 7d 64 }

  condition:
    any of them
}