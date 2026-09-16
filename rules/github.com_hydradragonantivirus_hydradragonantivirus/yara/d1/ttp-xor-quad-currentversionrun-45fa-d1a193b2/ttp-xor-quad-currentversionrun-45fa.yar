rule TTP_XOR_QUAD_CurrentVersionRun_45fa {
  strings:
    $key_45fa = { 16 95 [2] 32 9b [2] 19 b7 [2] 37 95 [2] 23 8e [2] 2c 94 [2] 32 89 [2] 30 88 [2] 2b 8e [2] 37 89 [2] 2b a6 }

  condition:
    any of them
}