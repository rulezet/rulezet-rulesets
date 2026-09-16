rule TTP_XOR_QUAD_CurrentVersionRun_71f9 {
  strings:
    $key_71f9 = { 22 96 [2] 06 98 [2] 2d b4 [2] 03 96 [2] 17 8d [2] 18 97 [2] 06 8a [2] 04 8b [2] 1f 8d [2] 03 8a [2] 1f a5 }

  condition:
    any of them
}