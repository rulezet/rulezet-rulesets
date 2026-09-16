rule TTP_XOR_QUAD_CurrentVersionRun_0428 {
  strings:
    $key_0428 = { 57 47 [2] 73 49 [2] 58 65 [2] 76 47 [2] 62 5c [2] 6d 46 [2] 73 5b [2] 71 5a [2] 6a 5c [2] 76 5b [2] 6a 74 }

  condition:
    any of them
}