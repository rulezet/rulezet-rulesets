rule TTP_XOR_QUAD_CurrentVersionRun_3a04 {
  strings:
    $key_3a04 = { 69 6b [2] 4d 65 [2] 66 49 [2] 48 6b [2] 5c 70 [2] 53 6a [2] 4d 77 [2] 4f 76 [2] 54 70 [2] 48 77 [2] 54 58 }

  condition:
    any of them
}