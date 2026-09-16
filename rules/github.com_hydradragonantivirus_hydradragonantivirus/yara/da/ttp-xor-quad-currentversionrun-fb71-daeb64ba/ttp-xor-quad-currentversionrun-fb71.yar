rule TTP_XOR_QUAD_CurrentVersionRun_fb71 {
  strings:
    $key_fb71 = { a8 1e [2] 8c 10 [2] a7 3c [2] 89 1e [2] 9d 05 [2] 92 1f [2] 8c 02 [2] 8e 03 [2] 95 05 [2] 89 02 [2] 95 2d }

  condition:
    any of them
}