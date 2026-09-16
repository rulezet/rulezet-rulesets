rule TTP_XOR_QUAD_CurrentVersionRun_0838 {
  strings:
    $key_0838 = { 5b 57 [2] 7f 59 [2] 54 75 [2] 7a 57 [2] 6e 4c [2] 61 56 [2] 7f 4b [2] 7d 4a [2] 66 4c [2] 7a 4b [2] 66 64 }

  condition:
    any of them
}