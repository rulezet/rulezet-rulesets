rule TTP_XOR_QUAD_CurrentVersionRun_71ea {
  strings:
    $key_71ea = { 22 85 [2] 06 8b [2] 2d a7 [2] 03 85 [2] 17 9e [2] 18 84 [2] 06 99 [2] 04 98 [2] 1f 9e [2] 03 99 [2] 1f b6 }

  condition:
    any of them
}