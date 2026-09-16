rule TTP_XOR_QUAD_CurrentVersionRun_6b49 {
  strings:
    $key_6b49 = { 38 26 [2] 1c 28 [2] 37 04 [2] 19 26 [2] 0d 3d [2] 02 27 [2] 1c 3a [2] 1e 3b [2] 05 3d [2] 19 3a [2] 05 15 }

  condition:
    any of them
}