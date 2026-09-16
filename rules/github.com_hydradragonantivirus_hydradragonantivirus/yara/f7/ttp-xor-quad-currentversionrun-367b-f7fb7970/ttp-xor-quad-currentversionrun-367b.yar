rule TTP_XOR_QUAD_CurrentVersionRun_367b {
  strings:
    $key_367b = { 65 14 [2] 41 1a [2] 6a 36 [2] 44 14 [2] 50 0f [2] 5f 15 [2] 41 08 [2] 43 09 [2] 58 0f [2] 44 08 [2] 58 27 }

  condition:
    any of them
}