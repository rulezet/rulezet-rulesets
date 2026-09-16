rule TTP_XOR_QUAD_CurrentVersionRun_fef8 {
  strings:
    $key_fef8 = { ad 97 [2] 89 99 [2] a2 b5 [2] 8c 97 [2] 98 8c [2] 97 96 [2] 89 8b [2] 8b 8a [2] 90 8c [2] 8c 8b [2] 90 a4 }

  condition:
    any of them
}