rule TTP_XOR_QUAD_CurrentVersionRun_f67b {
  strings:
    $key_f67b = { a5 14 [2] 81 1a [2] aa 36 [2] 84 14 [2] 90 0f [2] 9f 15 [2] 81 08 [2] 83 09 [2] 98 0f [2] 84 08 [2] 98 27 }

  condition:
    any of them
}