rule TTP_XOR_QUAD_CurrentVersionRun_780b {
  strings:
    $key_780b = { 2b 64 [2] 0f 6a [2] 24 46 [2] 0a 64 [2] 1e 7f [2] 11 65 [2] 0f 78 [2] 0d 79 [2] 16 7f [2] 0a 78 [2] 16 57 }

  condition:
    any of them
}