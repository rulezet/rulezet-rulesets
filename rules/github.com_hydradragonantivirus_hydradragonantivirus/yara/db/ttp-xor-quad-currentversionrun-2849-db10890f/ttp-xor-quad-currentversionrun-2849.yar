rule TTP_XOR_QUAD_CurrentVersionRun_2849 {
  strings:
    $key_2849 = { 7b 26 [2] 5f 28 [2] 74 04 [2] 5a 26 [2] 4e 3d [2] 41 27 [2] 5f 3a [2] 5d 3b [2] 46 3d [2] 5a 3a [2] 46 15 }

  condition:
    any of them
}