rule TTP_XOR_QUAD_CurrentVersionRun_3f49 {
  strings:
    $key_3f49 = { 6c 26 [2] 48 28 [2] 63 04 [2] 4d 26 [2] 59 3d [2] 56 27 [2] 48 3a [2] 4a 3b [2] 51 3d [2] 4d 3a [2] 51 15 }

  condition:
    any of them
}