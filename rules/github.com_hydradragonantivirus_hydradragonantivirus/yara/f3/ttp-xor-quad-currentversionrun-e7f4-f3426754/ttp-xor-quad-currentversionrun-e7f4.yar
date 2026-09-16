rule TTP_XOR_QUAD_CurrentVersionRun_e7f4 {
  strings:
    $key_e7f4 = { b4 9b [2] 90 95 [2] bb b9 [2] 95 9b [2] 81 80 [2] 8e 9a [2] 90 87 [2] 92 86 [2] 89 80 [2] 95 87 [2] 89 a8 }

  condition:
    any of them
}