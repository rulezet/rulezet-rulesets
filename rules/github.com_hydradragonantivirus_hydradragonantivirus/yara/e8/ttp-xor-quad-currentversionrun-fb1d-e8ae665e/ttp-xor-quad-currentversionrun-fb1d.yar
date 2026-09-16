rule TTP_XOR_QUAD_CurrentVersionRun_fb1d {
  strings:
    $key_fb1d = { a8 72 [2] 8c 7c [2] a7 50 [2] 89 72 [2] 9d 69 [2] 92 73 [2] 8c 6e [2] 8e 6f [2] 95 69 [2] 89 6e [2] 95 41 }

  condition:
    any of them
}