rule TTP_XOR_QUAD_CurrentVersionRun_4f08 {
  strings:
    $key_4f08 = { 1c 67 [2] 38 69 [2] 13 45 [2] 3d 67 [2] 29 7c [2] 26 66 [2] 38 7b [2] 3a 7a [2] 21 7c [2] 3d 7b [2] 21 54 }

  condition:
    any of them
}