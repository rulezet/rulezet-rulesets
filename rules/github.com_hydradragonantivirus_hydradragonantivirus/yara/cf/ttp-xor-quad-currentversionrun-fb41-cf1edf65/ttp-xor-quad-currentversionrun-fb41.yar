rule TTP_XOR_QUAD_CurrentVersionRun_fb41 {
  strings:
    $key_fb41 = { a8 2e [2] 8c 20 [2] a7 0c [2] 89 2e [2] 9d 35 [2] 92 2f [2] 8c 32 [2] 8e 33 [2] 95 35 [2] 89 32 [2] 95 1d }

  condition:
    any of them
}