rule TTP_XOR_QUAD_CurrentVersionRun_5444 {
  strings:
    $key_5444 = { 07 2b [2] 23 25 [2] 08 09 [2] 26 2b [2] 32 30 [2] 3d 2a [2] 23 37 [2] 21 36 [2] 3a 30 [2] 26 37 [2] 3a 18 }

  condition:
    any of them
}