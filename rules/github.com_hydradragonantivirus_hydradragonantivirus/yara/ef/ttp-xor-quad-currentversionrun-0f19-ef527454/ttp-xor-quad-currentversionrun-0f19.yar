rule TTP_XOR_QUAD_CurrentVersionRun_0f19 {
  strings:
    $key_0f19 = { 5c 76 [2] 78 78 [2] 53 54 [2] 7d 76 [2] 69 6d [2] 66 77 [2] 78 6a [2] 7a 6b [2] 61 6d [2] 7d 6a [2] 61 45 }

  condition:
    any of them
}