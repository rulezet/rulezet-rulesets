rule TTP_XOR_QUAD_CurrentVersionRun_2b49 {
  strings:
    $key_2b49 = { 78 26 [2] 5c 28 [2] 77 04 [2] 59 26 [2] 4d 3d [2] 42 27 [2] 5c 3a [2] 5e 3b [2] 45 3d [2] 59 3a [2] 45 15 }

  condition:
    any of them
}