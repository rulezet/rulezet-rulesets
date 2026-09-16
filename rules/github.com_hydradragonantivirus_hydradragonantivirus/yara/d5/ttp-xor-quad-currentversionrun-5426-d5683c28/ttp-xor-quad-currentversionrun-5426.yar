rule TTP_XOR_QUAD_CurrentVersionRun_5426 {
  strings:
    $key_5426 = { 07 49 [2] 23 47 [2] 08 6b [2] 26 49 [2] 32 52 [2] 3d 48 [2] 23 55 [2] 21 54 [2] 3a 52 [2] 26 55 [2] 3a 7a }

  condition:
    any of them
}