rule TTP_XOR_QUAD_CurrentVersionRun_7d49 {
  strings:
    $key_7d49 = { 2e 26 [2] 0a 28 [2] 21 04 [2] 0f 26 [2] 1b 3d [2] 14 27 [2] 0a 3a [2] 08 3b [2] 13 3d [2] 0f 3a [2] 13 15 }

  condition:
    any of them
}