rule TTP_XOR_QUAD_CurrentVersionRun_0d24 {
  strings:
    $key_0d24 = { 5e 4b [2] 7a 45 [2] 51 69 [2] 7f 4b [2] 6b 50 [2] 64 4a [2] 7a 57 [2] 78 56 [2] 63 50 [2] 7f 57 [2] 63 78 }

  condition:
    any of them
}