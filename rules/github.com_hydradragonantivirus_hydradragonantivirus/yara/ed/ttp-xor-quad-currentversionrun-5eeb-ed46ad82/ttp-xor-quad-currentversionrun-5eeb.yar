rule TTP_XOR_QUAD_CurrentVersionRun_5eeb {
  strings:
    $key_5eeb = { 0d 84 [2] 29 8a [2] 02 a6 [2] 2c 84 [2] 38 9f [2] 37 85 [2] 29 98 [2] 2b 99 [2] 30 9f [2] 2c 98 [2] 30 b7 }

  condition:
    any of them
}