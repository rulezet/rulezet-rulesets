rule TTP_XOR_QUAD_CurrentVersionRun_fb7a {
  strings:
    $key_fb7a = { a8 15 [2] 8c 1b [2] a7 37 [2] 89 15 [2] 9d 0e [2] 92 14 [2] 8c 09 [2] 8e 08 [2] 95 0e [2] 89 09 [2] 95 26 }

  condition:
    any of them
}