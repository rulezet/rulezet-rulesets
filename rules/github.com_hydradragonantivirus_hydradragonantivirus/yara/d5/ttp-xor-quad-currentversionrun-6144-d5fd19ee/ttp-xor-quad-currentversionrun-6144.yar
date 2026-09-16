rule TTP_XOR_QUAD_CurrentVersionRun_6144 {
  strings:
    $key_6144 = { 32 2b [2] 16 25 [2] 3d 09 [2] 13 2b [2] 07 30 [2] 08 2a [2] 16 37 [2] 14 36 [2] 0f 30 [2] 13 37 [2] 0f 18 }

  condition:
    any of them
}