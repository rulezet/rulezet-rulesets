rule TTP_XOR_QUAD_CurrentVersionRun_4304 {
  strings:
    $key_4304 = { 10 6b [2] 34 65 [2] 1f 49 [2] 31 6b [2] 25 70 [2] 2a 6a [2] 34 77 [2] 36 76 [2] 2d 70 [2] 31 77 [2] 2d 58 }

  condition:
    any of them
}