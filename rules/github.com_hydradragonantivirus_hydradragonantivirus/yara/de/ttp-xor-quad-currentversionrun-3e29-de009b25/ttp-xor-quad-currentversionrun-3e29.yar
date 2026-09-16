rule TTP_XOR_QUAD_CurrentVersionRun_3e29 {
  strings:
    $key_3e29 = { 6d 46 [2] 49 48 [2] 62 64 [2] 4c 46 [2] 58 5d [2] 57 47 [2] 49 5a [2] 4b 5b [2] 50 5d [2] 4c 5a [2] 50 75 }

  condition:
    any of them
}