rule TTP_XOR_QUAD_CurrentVersionRun_1249 {
  strings:
    $key_1249 = { 41 26 [2] 65 28 [2] 4e 04 [2] 60 26 [2] 74 3d [2] 7b 27 [2] 65 3a [2] 67 3b [2] 7c 3d [2] 60 3a [2] 7c 15 }

  condition:
    any of them
}