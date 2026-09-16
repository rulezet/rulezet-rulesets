rule TTP_XOR_QUAD_CurrentVersionRun_557d {
  strings:
    $key_557d = { 06 12 [2] 22 1c [2] 09 30 [2] 27 12 [2] 33 09 [2] 3c 13 [2] 22 0e [2] 20 0f [2] 3b 09 [2] 27 0e [2] 3b 21 }

  condition:
    any of them
}