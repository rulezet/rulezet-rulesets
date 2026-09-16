rule TTP_XOR_QUAD_CurrentVersionRun_47fa {
  strings:
    $key_47fa = { 14 95 [2] 30 9b [2] 1b b7 [2] 35 95 [2] 21 8e [2] 2e 94 [2] 30 89 [2] 32 88 [2] 29 8e [2] 35 89 [2] 29 a6 }

  condition:
    any of them
}