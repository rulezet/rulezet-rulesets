rule TTP_XOR_QUAD_CurrentVersionRun_e1ea {
  strings:
    $key_e1ea = { b2 85 [2] 96 8b [2] bd a7 [2] 93 85 [2] 87 9e [2] 88 84 [2] 96 99 [2] 94 98 [2] 8f 9e [2] 93 99 [2] 8f b6 }

  condition:
    any of them
}