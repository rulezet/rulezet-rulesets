rule TTP_XOR_QUAD_CurrentVersionRun_6128 {
  strings:
    $key_6128 = { 32 47 [2] 16 49 [2] 3d 65 [2] 13 47 [2] 07 5c [2] 08 46 [2] 16 5b [2] 14 5a [2] 0f 5c [2] 13 5b [2] 0f 74 }

  condition:
    any of them
}