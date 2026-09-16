rule TTP_XOR_QUAD_CurrentVersionRun_f959 {
  strings:
    $key_f959 = { aa 36 [2] 8e 38 [2] a5 14 [2] 8b 36 [2] 9f 2d [2] 90 37 [2] 8e 2a [2] 8c 2b [2] 97 2d [2] 8b 2a [2] 97 05 }

  condition:
    any of them
}