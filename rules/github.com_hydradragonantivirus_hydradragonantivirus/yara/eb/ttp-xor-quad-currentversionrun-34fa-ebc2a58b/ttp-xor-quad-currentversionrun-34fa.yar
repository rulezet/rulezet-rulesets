rule TTP_XOR_QUAD_CurrentVersionRun_34fa {
  strings:
    $key_34fa = { 67 95 [2] 43 9b [2] 68 b7 [2] 46 95 [2] 52 8e [2] 5d 94 [2] 43 89 [2] 41 88 [2] 5a 8e [2] 46 89 [2] 5a a6 }

  condition:
    any of them
}