rule TTP_XOR_QUAD_CurrentVersionRun_f7ac {
  strings:
    $key_f7ac = { a4 c3 [2] 80 cd [2] ab e1 [2] 85 c3 [2] 91 d8 [2] 9e c2 [2] 80 df [2] 82 de [2] 99 d8 [2] 85 df [2] 99 f0 }

  condition:
    any of them
}