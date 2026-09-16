rule TTP_XOR_QUAD_CurrentVersionRun_25eb {
  strings:
    $key_25eb = { 76 84 [2] 52 8a [2] 79 a6 [2] 57 84 [2] 43 9f [2] 4c 85 [2] 52 98 [2] 50 99 [2] 4b 9f [2] 57 98 [2] 4b b7 }

  condition:
    any of them
}