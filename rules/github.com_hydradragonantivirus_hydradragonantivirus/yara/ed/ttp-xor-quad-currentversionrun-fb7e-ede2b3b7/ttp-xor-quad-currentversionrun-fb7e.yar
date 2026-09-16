rule TTP_XOR_QUAD_CurrentVersionRun_fb7e {
  strings:
    $key_fb7e = { a8 11 [2] 8c 1f [2] a7 33 [2] 89 11 [2] 9d 0a [2] 92 10 [2] 8c 0d [2] 8e 0c [2] 95 0a [2] 89 0d [2] 95 22 }

  condition:
    any of them
}