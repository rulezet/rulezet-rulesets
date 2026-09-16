rule TTP_XOR_QUAD_CurrentVersionRun_46eb {
  strings:
    $key_46eb = { 15 84 [2] 31 8a [2] 1a a6 [2] 34 84 [2] 20 9f [2] 2f 85 [2] 31 98 [2] 33 99 [2] 28 9f [2] 34 98 [2] 28 b7 }

  condition:
    any of them
}