rule TTP_XOR_QUAD_CurrentVersionRun_0824 {
  strings:
    $key_0824 = { 5b 4b [2] 7f 45 [2] 54 69 [2] 7a 4b [2] 6e 50 [2] 61 4a [2] 7f 57 [2] 7d 56 [2] 66 50 [2] 7a 57 [2] 66 78 }

  condition:
    any of them
}