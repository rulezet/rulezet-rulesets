rule TTP_XOR_QUAD_CurrentVersionRun_e7f9 {
  strings:
    $key_e7f9 = { b4 96 [2] 90 98 [2] bb b4 [2] 95 96 [2] 81 8d [2] 8e 97 [2] 90 8a [2] 92 8b [2] 89 8d [2] 95 8a [2] 89 a5 }

  condition:
    any of them
}