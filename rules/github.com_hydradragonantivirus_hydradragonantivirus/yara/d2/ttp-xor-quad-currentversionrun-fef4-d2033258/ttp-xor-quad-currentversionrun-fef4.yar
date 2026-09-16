rule TTP_XOR_QUAD_CurrentVersionRun_fef4 {
  strings:
    $key_fef4 = { ad 9b [2] 89 95 [2] a2 b9 [2] 8c 9b [2] 98 80 [2] 97 9a [2] 89 87 [2] 8b 86 [2] 90 80 [2] 8c 87 [2] 90 a8 }

  condition:
    any of them
}