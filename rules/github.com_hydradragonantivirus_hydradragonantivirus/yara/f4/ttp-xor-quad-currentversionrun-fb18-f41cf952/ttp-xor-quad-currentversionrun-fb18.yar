rule TTP_XOR_QUAD_CurrentVersionRun_fb18 {
  strings:
    $key_fb18 = { a8 77 [2] 8c 79 [2] a7 55 [2] 89 77 [2] 9d 6c [2] 92 76 [2] 8c 6b [2] 8e 6a [2] 95 6c [2] 89 6b [2] 95 44 }

  condition:
    any of them
}