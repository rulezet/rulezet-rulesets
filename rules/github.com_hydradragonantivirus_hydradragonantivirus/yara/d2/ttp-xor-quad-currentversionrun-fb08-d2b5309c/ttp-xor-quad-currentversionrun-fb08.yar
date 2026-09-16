rule TTP_XOR_QUAD_CurrentVersionRun_fb08 {
  strings:
    $key_fb08 = { a8 67 [2] 8c 69 [2] a7 45 [2] 89 67 [2] 9d 7c [2] 92 66 [2] 8c 7b [2] 8e 7a [2] 95 7c [2] 89 7b [2] 95 54 }

  condition:
    any of them
}