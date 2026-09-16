rule TTP_XOR_QUAD_CurrentVersionRun_4409 {
  strings:
    $key_4409 = { 17 66 [2] 33 68 [2] 18 44 [2] 36 66 [2] 22 7d [2] 2d 67 [2] 33 7a [2] 31 7b [2] 2a 7d [2] 36 7a [2] 2a 55 }

  condition:
    any of them
}