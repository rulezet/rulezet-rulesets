rule TTP_XOR_QUAD_CurrentVersionRun_67eb {
  strings:
    $key_67eb = { 34 84 [2] 10 8a [2] 3b a6 [2] 15 84 [2] 01 9f [2] 0e 85 [2] 10 98 [2] 12 99 [2] 09 9f [2] 15 98 [2] 09 b7 }

  condition:
    any of them
}