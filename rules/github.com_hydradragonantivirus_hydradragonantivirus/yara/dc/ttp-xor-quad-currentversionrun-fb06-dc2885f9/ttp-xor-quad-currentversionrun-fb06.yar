rule TTP_XOR_QUAD_CurrentVersionRun_fb06 {
  strings:
    $key_fb06 = { a8 69 [2] 8c 67 [2] a7 4b [2] 89 69 [2] 9d 72 [2] 92 68 [2] 8c 75 [2] 8e 74 [2] 95 72 [2] 89 75 [2] 95 5a }

  condition:
    any of them
}