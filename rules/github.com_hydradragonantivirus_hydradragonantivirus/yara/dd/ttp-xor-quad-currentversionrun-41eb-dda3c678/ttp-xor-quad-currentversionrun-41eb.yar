rule TTP_XOR_QUAD_CurrentVersionRun_41eb {
  strings:
    $key_41eb = { 12 84 [2] 36 8a [2] 1d a6 [2] 33 84 [2] 27 9f [2] 28 85 [2] 36 98 [2] 34 99 [2] 2f 9f [2] 33 98 [2] 2f b7 }

  condition:
    any of them
}