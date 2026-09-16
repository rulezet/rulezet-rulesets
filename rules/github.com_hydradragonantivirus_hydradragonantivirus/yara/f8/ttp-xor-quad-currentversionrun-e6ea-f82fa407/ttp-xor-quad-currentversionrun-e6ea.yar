rule TTP_XOR_QUAD_CurrentVersionRun_e6ea {
  strings:
    $key_e6ea = { b5 85 [2] 91 8b [2] ba a7 [2] 94 85 [2] 80 9e [2] 8f 84 [2] 91 99 [2] 93 98 [2] 88 9e [2] 94 99 [2] 88 b6 }

  condition:
    any of them
}