rule TTP_XOR_QUAD_CurrentVersionRun_60eb {
  strings:
    $key_60eb = { 33 84 [2] 17 8a [2] 3c a6 [2] 12 84 [2] 06 9f [2] 09 85 [2] 17 98 [2] 15 99 [2] 0e 9f [2] 12 98 [2] 0e b7 }

  condition:
    any of them
}