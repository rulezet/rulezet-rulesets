rule TTP_XOR_QUAD_CurrentVersionRun_28fa {
  strings:
    $key_28fa = { 7b 95 [2] 5f 9b [2] 74 b7 [2] 5a 95 [2] 4e 8e [2] 41 94 [2] 5f 89 [2] 5d 88 [2] 46 8e [2] 5a 89 [2] 46 a6 }

  condition:
    any of them
}