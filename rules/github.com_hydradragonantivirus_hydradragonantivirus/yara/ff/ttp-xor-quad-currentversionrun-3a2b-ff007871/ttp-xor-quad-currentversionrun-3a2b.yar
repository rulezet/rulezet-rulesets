rule TTP_XOR_QUAD_CurrentVersionRun_3a2b {
  strings:
    $key_3a2b = { 69 44 [2] 4d 4a [2] 66 66 [2] 48 44 [2] 5c 5f [2] 53 45 [2] 4d 58 [2] 4f 59 [2] 54 5f [2] 48 58 [2] 54 77 }

  condition:
    any of them
}