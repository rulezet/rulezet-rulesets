rule TTP_XOR_QUAD_CurrentVersionRun_01eb {
  strings:
    $key_01eb = { 52 84 [2] 76 8a [2] 5d a6 [2] 73 84 [2] 67 9f [2] 68 85 [2] 76 98 [2] 74 99 [2] 6f 9f [2] 73 98 [2] 6f b7 }

  condition:
    any of them
}