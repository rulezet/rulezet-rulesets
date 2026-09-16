rule TTP_XOR_QUAD_CurrentVersionRun_71fa {
  strings:
    $key_71fa = { 22 95 [2] 06 9b [2] 2d b7 [2] 03 95 [2] 17 8e [2] 18 94 [2] 06 89 [2] 04 88 [2] 1f 8e [2] 03 89 [2] 1f a6 }

  condition:
    any of them
}