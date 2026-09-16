rule TTP_XOR_QUAD_CurrentVersionRun_0335 {
  strings:
    $key_0335 = { 50 5a [2] 74 54 [2] 5f 78 [2] 71 5a [2] 65 41 [2] 6a 5b [2] 74 46 [2] 76 47 [2] 6d 41 [2] 71 46 [2] 6d 69 }

  condition:
    any of them
}