rule TTP_XOR_QUAD_CurrentVersionRun_f1ea {
  strings:
    $key_f1ea = { a2 85 [2] 86 8b [2] ad a7 [2] 83 85 [2] 97 9e [2] 98 84 [2] 86 99 [2] 84 98 [2] 9f 9e [2] 83 99 [2] 9f b6 }

  condition:
    any of them
}