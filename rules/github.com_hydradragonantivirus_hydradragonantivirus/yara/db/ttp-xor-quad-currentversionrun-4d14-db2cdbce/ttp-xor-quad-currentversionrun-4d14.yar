rule TTP_XOR_QUAD_CurrentVersionRun_4d14 {
  strings:
    $key_4d14 = { 1e 7b [2] 3a 75 [2] 11 59 [2] 3f 7b [2] 2b 60 [2] 24 7a [2] 3a 67 [2] 38 66 [2] 23 60 [2] 3f 67 [2] 23 48 }

  condition:
    any of them
}