rule TTP_XOR_QUAD_CurrentVersionRun_0d59 {
  strings:
    $key_0d59 = { 5e 36 [2] 7a 38 [2] 51 14 [2] 7f 36 [2] 6b 2d [2] 64 37 [2] 7a 2a [2] 78 2b [2] 63 2d [2] 7f 2a [2] 63 05 }

  condition:
    any of them
}