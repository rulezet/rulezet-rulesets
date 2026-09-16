rule TTP_XOR_QUAD_CurrentVersionRun_538a {
  strings:
    $key_538a = { 00 e5 [2] 24 eb [2] 0f c7 [2] 21 e5 [2] 35 fe [2] 3a e4 [2] 24 f9 [2] 26 f8 [2] 3d fe [2] 21 f9 [2] 3d d6 }

  condition:
    any of them
}