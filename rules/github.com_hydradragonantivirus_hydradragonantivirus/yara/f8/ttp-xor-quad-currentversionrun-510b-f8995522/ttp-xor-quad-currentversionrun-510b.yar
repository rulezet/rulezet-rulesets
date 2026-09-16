rule TTP_XOR_QUAD_CurrentVersionRun_510b {
  strings:
    $key_510b = { 02 64 [2] 26 6a [2] 0d 46 [2] 23 64 [2] 37 7f [2] 38 65 [2] 26 78 [2] 24 79 [2] 3f 7f [2] 23 78 [2] 3f 57 }

  condition:
    any of them
}