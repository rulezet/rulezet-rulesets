rule TTP_XOR_QUAD_CurrentVersionRun_58ea {
  strings:
    $key_58ea = { 0b 85 [2] 2f 8b [2] 04 a7 [2] 2a 85 [2] 3e 9e [2] 31 84 [2] 2f 99 [2] 2d 98 [2] 36 9e [2] 2a 99 [2] 36 b6 }

  condition:
    any of them
}