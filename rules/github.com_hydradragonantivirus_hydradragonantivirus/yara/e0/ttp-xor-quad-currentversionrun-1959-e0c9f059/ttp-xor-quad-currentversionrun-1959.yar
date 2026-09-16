rule TTP_XOR_QUAD_CurrentVersionRun_1959 {
  strings:
    $key_1959 = { 4a 36 [2] 6e 38 [2] 45 14 [2] 6b 36 [2] 7f 2d [2] 70 37 [2] 6e 2a [2] 6c 2b [2] 77 2d [2] 6b 2a [2] 77 05 }

  condition:
    any of them
}