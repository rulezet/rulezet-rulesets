rule TTP_XOR_QUAD_CurrentVersionRun_2604 {
  strings:
    $key_2604 = { 75 6b [2] 51 65 [2] 7a 49 [2] 54 6b [2] 40 70 [2] 4f 6a [2] 51 77 [2] 53 76 [2] 48 70 [2] 54 77 [2] 48 58 }

  condition:
    any of them
}