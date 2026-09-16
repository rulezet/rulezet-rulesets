rule TTP_XOR_QUAD_CurrentVersionRun_57f9 {
  strings:
    $key_57f9 = { 04 96 [2] 20 98 [2] 0b b4 [2] 25 96 [2] 31 8d [2] 3e 97 [2] 20 8a [2] 22 8b [2] 39 8d [2] 25 8a [2] 39 a5 }

  condition:
    any of them
}