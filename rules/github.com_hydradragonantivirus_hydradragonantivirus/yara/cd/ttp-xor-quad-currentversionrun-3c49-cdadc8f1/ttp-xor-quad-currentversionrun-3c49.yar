rule TTP_XOR_QUAD_CurrentVersionRun_3c49 {
  strings:
    $key_3c49 = { 6f 26 [2] 4b 28 [2] 60 04 [2] 4e 26 [2] 5a 3d [2] 55 27 [2] 4b 3a [2] 49 3b [2] 52 3d [2] 4e 3a [2] 52 15 }

  condition:
    any of them
}