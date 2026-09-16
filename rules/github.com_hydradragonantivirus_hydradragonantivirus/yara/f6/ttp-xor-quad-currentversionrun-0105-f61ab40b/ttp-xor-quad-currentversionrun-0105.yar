rule TTP_XOR_QUAD_CurrentVersionRun_0105 {
  strings:
    $key_0105 = { 52 6a [2] 76 64 [2] 5d 48 [2] 73 6a [2] 67 71 [2] 68 6b [2] 76 76 [2] 74 77 [2] 6f 71 [2] 73 76 [2] 6f 59 }

  condition:
    any of them
}