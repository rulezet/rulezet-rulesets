rule TTP_XOR_QUAD_CurrentVersionRun_6329 {
  strings:
    $key_6329 = { 30 46 [2] 14 48 [2] 3f 64 [2] 11 46 [2] 05 5d [2] 0a 47 [2] 14 5a [2] 16 5b [2] 0d 5d [2] 11 5a [2] 0d 75 }

  condition:
    any of them
}