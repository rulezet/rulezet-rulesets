rule TTP_XOR_QUAD_CurrentVersionRun_fb49 {
  strings:
    $key_fb49 = { a8 26 [2] 8c 28 [2] a7 04 [2] 89 26 [2] 9d 3d [2] 92 27 [2] 8c 3a [2] 8e 3b [2] 95 3d [2] 89 3a [2] 95 15 }

  condition:
    any of them
}