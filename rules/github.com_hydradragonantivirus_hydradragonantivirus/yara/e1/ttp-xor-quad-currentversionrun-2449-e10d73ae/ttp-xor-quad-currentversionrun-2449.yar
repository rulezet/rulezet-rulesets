rule TTP_XOR_QUAD_CurrentVersionRun_2449 {
  strings:
    $key_2449 = { 77 26 [2] 53 28 [2] 78 04 [2] 56 26 [2] 42 3d [2] 4d 27 [2] 53 3a [2] 51 3b [2] 4a 3d [2] 56 3a [2] 4a 15 }

  condition:
    any of them
}