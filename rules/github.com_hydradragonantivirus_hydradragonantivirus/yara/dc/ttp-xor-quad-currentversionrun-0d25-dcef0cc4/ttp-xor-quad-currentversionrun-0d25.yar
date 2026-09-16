rule TTP_XOR_QUAD_CurrentVersionRun_0d25 {
  strings:
    $key_0d25 = { 5e 4a [2] 7a 44 [2] 51 68 [2] 7f 4a [2] 6b 51 [2] 64 4b [2] 7a 56 [2] 78 57 [2] 63 51 [2] 7f 56 [2] 63 79 }

  condition:
    any of them
}