rule TTP_XOR_QUAD_CurrentVersionRun_54e5 {
  strings:
    $key_54e5 = { 07 8a [2] 23 84 [2] 08 a8 [2] 26 8a [2] 32 91 [2] 3d 8b [2] 23 96 [2] 21 97 [2] 3a 91 [2] 26 96 [2] 3a b9 }

  condition:
    any of them
}