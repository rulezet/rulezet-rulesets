rule TTP_XOR_QUAD_CurrentVersionRun_747b {
  strings:
    $key_747b = { 27 14 [2] 03 1a [2] 28 36 [2] 06 14 [2] 12 0f [2] 1d 15 [2] 03 08 [2] 01 09 [2] 1a 0f [2] 06 08 [2] 1a 27 }

  condition:
    any of them
}