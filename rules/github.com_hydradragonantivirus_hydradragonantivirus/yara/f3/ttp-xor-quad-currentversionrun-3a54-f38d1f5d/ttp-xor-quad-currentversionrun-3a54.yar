rule TTP_XOR_QUAD_CurrentVersionRun_3a54 {
  strings:
    $key_3a54 = { 69 3b [2] 4d 35 [2] 66 19 [2] 48 3b [2] 5c 20 [2] 53 3a [2] 4d 27 [2] 4f 26 [2] 54 20 [2] 48 27 [2] 54 08 }

  condition:
    any of them
}