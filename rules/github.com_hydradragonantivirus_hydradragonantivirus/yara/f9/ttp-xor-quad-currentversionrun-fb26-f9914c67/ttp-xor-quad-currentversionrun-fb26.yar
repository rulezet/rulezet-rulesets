rule TTP_XOR_QUAD_CurrentVersionRun_fb26 {
  strings:
    $key_fb26 = { a8 49 [2] 8c 47 [2] a7 6b [2] 89 49 [2] 9d 52 [2] 92 48 [2] 8c 55 [2] 8e 54 [2] 95 52 [2] 89 55 [2] 95 7a }

  condition:
    any of them
}