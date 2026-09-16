rule TTP_XOR_QUAD_CurrentVersionRun_fb6c {
  strings:
    $key_fb6c = { a8 03 [2] 8c 0d [2] a7 21 [2] 89 03 [2] 9d 18 [2] 92 02 [2] 8c 1f [2] 8e 1e [2] 95 18 [2] 89 1f [2] 95 30 }

  condition:
    any of them
}