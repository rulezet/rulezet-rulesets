rule TTP_XOR_QUAD_CurrentVersionRun_3a49 {
  strings:
    $key_3a49 = { 69 26 [2] 4d 28 [2] 66 04 [2] 48 26 [2] 5c 3d [2] 53 27 [2] 4d 3a [2] 4f 3b [2] 54 3d [2] 48 3a [2] 54 15 }

  condition:
    any of them
}