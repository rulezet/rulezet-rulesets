rule TTP_XOR_QUAD_CurrentVersionRun_787b {
  strings:
    $key_787b = { 2b 14 [2] 0f 1a [2] 24 36 [2] 0a 14 [2] 1e 0f [2] 11 15 [2] 0f 08 [2] 0d 09 [2] 16 0f [2] 0a 08 [2] 16 27 }

  condition:
    any of them
}