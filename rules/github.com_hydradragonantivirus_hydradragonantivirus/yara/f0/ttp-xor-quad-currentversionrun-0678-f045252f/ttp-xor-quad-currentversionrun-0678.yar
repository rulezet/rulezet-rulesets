rule TTP_XOR_QUAD_CurrentVersionRun_0678 {
  strings:
    $key_0678 = { 55 17 [2] 71 19 [2] 5a 35 [2] 74 17 [2] 60 0c [2] 6f 16 [2] 71 0b [2] 73 0a [2] 68 0c [2] 74 0b [2] 68 24 }

  condition:
    any of them
}