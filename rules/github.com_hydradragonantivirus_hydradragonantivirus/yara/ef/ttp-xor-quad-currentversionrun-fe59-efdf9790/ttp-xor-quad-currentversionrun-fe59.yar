rule TTP_XOR_QUAD_CurrentVersionRun_fe59 {
  strings:
    $key_fe59 = { ad 36 [2] 89 38 [2] a2 14 [2] 8c 36 [2] 98 2d [2] 97 37 [2] 89 2a [2] 8b 2b [2] 90 2d [2] 8c 2a [2] 90 05 }

  condition:
    any of them
}