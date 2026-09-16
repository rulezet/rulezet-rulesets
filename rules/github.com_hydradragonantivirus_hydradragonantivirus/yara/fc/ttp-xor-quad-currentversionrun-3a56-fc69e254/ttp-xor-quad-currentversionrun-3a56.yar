rule TTP_XOR_QUAD_CurrentVersionRun_3a56 {
  strings:
    $key_3a56 = { 69 39 [2] 4d 37 [2] 66 1b [2] 48 39 [2] 5c 22 [2] 53 38 [2] 4d 25 [2] 4f 24 [2] 54 22 [2] 48 25 [2] 54 0a }

  condition:
    any of them
}