rule TTP_XOR_QUAD_CurrentVersionRun_fb39 {
  strings:
    $key_fb39 = { a8 56 [2] 8c 58 [2] a7 74 [2] 89 56 [2] 9d 4d [2] 92 57 [2] 8c 4a [2] 8e 4b [2] 95 4d [2] 89 4a [2] 95 65 }

  condition:
    any of them
}