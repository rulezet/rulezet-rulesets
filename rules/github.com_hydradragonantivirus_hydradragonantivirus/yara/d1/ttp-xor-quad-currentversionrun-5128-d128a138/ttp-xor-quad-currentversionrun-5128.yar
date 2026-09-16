rule TTP_XOR_QUAD_CurrentVersionRun_5128 {
  strings:
    $key_5128 = { 02 47 [2] 26 49 [2] 0d 65 [2] 23 47 [2] 37 5c [2] 38 46 [2] 26 5b [2] 24 5a [2] 3f 5c [2] 23 5b [2] 3f 74 }

  condition:
    any of them
}