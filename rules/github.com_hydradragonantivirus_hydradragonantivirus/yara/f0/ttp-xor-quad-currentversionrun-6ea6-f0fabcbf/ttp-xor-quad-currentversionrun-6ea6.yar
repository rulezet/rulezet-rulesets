rule TTP_XOR_QUAD_CurrentVersionRun_6ea6 {
  strings:
    $key_6ea6 = { 3d c9 [2] 19 c7 [2] 32 eb [2] 1c c9 [2] 08 d2 [2] 07 c8 [2] 19 d5 [2] 1b d4 [2] 00 d2 [2] 1c d5 [2] 00 fa }

  condition:
    any of them
}