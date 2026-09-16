rule TTP_XOR_QUAD_CurrentVersionRun_557b {
  strings:
    $key_557b = { 06 14 [2] 22 1a [2] 09 36 [2] 27 14 [2] 33 0f [2] 3c 15 [2] 22 08 [2] 20 09 [2] 3b 0f [2] 27 08 [2] 3b 27 }

  condition:
    any of them
}