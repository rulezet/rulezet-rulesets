rule TTP_XOR_QUAD_CurrentVersionRun_0328 {
  strings:
    $key_0328 = { 50 47 [2] 74 49 [2] 5f 65 [2] 71 47 [2] 65 5c [2] 6a 46 [2] 74 5b [2] 76 5a [2] 6d 5c [2] 71 5b [2] 6d 74 }

  condition:
    any of them
}