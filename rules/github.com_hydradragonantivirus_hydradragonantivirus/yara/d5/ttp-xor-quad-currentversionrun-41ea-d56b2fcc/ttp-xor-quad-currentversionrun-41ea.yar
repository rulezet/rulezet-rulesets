rule TTP_XOR_QUAD_CurrentVersionRun_41ea {
  strings:
    $key_41ea = { 12 85 [2] 36 8b [2] 1d a7 [2] 33 85 [2] 27 9e [2] 28 84 [2] 36 99 [2] 34 98 [2] 2f 9e [2] 33 99 [2] 2f b6 }

  condition:
    any of them
}