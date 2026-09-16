rule TTP_XOR_QUAD_CurrentVersionRun_147b {
  strings:
    $key_147b = { 47 14 [2] 63 1a [2] 48 36 [2] 66 14 [2] 72 0f [2] 7d 15 [2] 63 08 [2] 61 09 [2] 7a 0f [2] 66 08 [2] 7a 27 }

  condition:
    any of them
}