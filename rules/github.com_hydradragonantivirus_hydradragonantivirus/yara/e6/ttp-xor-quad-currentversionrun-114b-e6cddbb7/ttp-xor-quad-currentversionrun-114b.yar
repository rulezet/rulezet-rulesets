rule TTP_XOR_QUAD_CurrentVersionRun_114b {
  strings:
    $key_114b = { 42 24 [2] 66 2a [2] 4d 06 [2] 63 24 [2] 77 3f [2] 78 25 [2] 66 38 [2] 64 39 [2] 7f 3f [2] 63 38 [2] 7f 17 }

  condition:
    any of them
}