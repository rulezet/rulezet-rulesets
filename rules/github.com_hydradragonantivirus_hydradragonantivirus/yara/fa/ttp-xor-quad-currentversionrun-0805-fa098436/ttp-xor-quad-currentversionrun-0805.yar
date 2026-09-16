rule TTP_XOR_QUAD_CurrentVersionRun_0805 {
  strings:
    $key_0805 = { 5b 6a [2] 7f 64 [2] 54 48 [2] 7a 6a [2] 6e 71 [2] 61 6b [2] 7f 76 [2] 7d 77 [2] 66 71 [2] 7a 76 [2] 66 59 }

  condition:
    any of them
}