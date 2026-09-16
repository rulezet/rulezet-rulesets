rule TTP_XOR_QUAD_CurrentVersionRun_fb4c {
  strings:
    $key_fb4c = { a8 23 [2] 8c 2d [2] a7 01 [2] 89 23 [2] 9d 38 [2] 92 22 [2] 8c 3f [2] 8e 3e [2] 95 38 [2] 89 3f [2] 95 10 }

  condition:
    any of them
}