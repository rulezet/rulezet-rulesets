rule TTP_XOR_QUAD_CurrentVersionRun_fb2c {
  strings:
    $key_fb2c = { a8 43 [2] 8c 4d [2] a7 61 [2] 89 43 [2] 9d 58 [2] 92 42 [2] 8c 5f [2] 8e 5e [2] 95 58 [2] 89 5f [2] 95 70 }

  condition:
    any of them
}