rule TTP_XOR_QUAD_CurrentVersionRun_76fa {
  strings:
    $key_76fa = { 25 95 [2] 01 9b [2] 2a b7 [2] 04 95 [2] 10 8e [2] 1f 94 [2] 01 89 [2] 03 88 [2] 18 8e [2] 04 89 [2] 18 a6 }

  condition:
    any of them
}