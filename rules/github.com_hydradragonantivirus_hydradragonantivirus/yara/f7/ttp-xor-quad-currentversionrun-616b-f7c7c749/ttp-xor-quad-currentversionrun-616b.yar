rule TTP_XOR_QUAD_CurrentVersionRun_616b {
  strings:
    $key_616b = { 32 04 [2] 16 0a [2] 3d 26 [2] 13 04 [2] 07 1f [2] 08 05 [2] 16 18 [2] 14 19 [2] 0f 1f [2] 13 18 [2] 0f 37 }

  condition:
    any of them
}