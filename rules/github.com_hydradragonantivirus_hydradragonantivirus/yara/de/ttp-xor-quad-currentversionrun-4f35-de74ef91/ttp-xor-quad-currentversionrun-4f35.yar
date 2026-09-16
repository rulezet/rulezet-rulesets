rule TTP_XOR_QUAD_CurrentVersionRun_4f35 {
  strings:
    $key_4f35 = { 1c 5a [2] 38 54 [2] 13 78 [2] 3d 5a [2] 29 41 [2] 26 5b [2] 38 46 [2] 3a 47 [2] 21 41 [2] 3d 46 [2] 21 69 }

  condition:
    any of them
}