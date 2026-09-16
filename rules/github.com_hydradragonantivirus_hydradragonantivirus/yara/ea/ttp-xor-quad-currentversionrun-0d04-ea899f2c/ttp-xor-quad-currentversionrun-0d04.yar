rule TTP_XOR_QUAD_CurrentVersionRun_0d04 {
  strings:
    $key_0d04 = { 5e 6b [2] 7a 65 [2] 51 49 [2] 7f 6b [2] 6b 70 [2] 64 6a [2] 7a 77 [2] 78 76 [2] 63 70 [2] 7f 77 [2] 63 58 }

  condition:
    any of them
}