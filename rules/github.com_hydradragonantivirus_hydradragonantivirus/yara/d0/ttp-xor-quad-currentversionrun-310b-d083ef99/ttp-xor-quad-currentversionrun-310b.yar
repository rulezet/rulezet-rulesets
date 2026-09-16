rule TTP_XOR_QUAD_CurrentVersionRun_310b {
  strings:
    $key_310b = { 62 64 [2] 46 6a [2] 6d 46 [2] 43 64 [2] 57 7f [2] 58 65 [2] 46 78 [2] 44 79 [2] 5f 7f [2] 43 78 [2] 5f 57 }

  condition:
    any of them
}