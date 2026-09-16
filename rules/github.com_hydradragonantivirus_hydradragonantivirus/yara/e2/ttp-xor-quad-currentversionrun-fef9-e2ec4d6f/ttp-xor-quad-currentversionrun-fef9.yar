rule TTP_XOR_QUAD_CurrentVersionRun_fef9 {
  strings:
    $key_fef9 = { ad 96 [2] 89 98 [2] a2 b4 [2] 8c 96 [2] 98 8d [2] 97 97 [2] 89 8a [2] 8b 8b [2] 90 8d [2] 8c 8a [2] 90 a5 }

  condition:
    any of them
}