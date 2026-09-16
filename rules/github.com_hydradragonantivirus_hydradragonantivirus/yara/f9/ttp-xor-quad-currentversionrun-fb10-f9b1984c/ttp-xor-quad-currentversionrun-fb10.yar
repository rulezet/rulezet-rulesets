rule TTP_XOR_QUAD_CurrentVersionRun_fb10 {
  strings:
    $key_fb10 = { a8 7f [2] 8c 71 [2] a7 5d [2] 89 7f [2] 9d 64 [2] 92 7e [2] 8c 63 [2] 8e 62 [2] 95 64 [2] 89 63 [2] 95 4c }

  condition:
    any of them
}