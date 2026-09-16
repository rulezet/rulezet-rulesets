rule TTP_XOR_QUAD_CurrentVersionRun_6126 {
  strings:
    $key_6126 = { 32 49 [2] 16 47 [2] 3d 6b [2] 13 49 [2] 07 52 [2] 08 48 [2] 16 55 [2] 14 54 [2] 0f 52 [2] 13 55 [2] 0f 7a }

  condition:
    any of them
}