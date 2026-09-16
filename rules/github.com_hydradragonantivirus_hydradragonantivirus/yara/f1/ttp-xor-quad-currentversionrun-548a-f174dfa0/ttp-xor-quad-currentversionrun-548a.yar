rule TTP_XOR_QUAD_CurrentVersionRun_548a {
  strings:
    $key_548a = { 07 e5 [2] 23 eb [2] 08 c7 [2] 26 e5 [2] 32 fe [2] 3d e4 [2] 23 f9 [2] 21 f8 [2] 3a fe [2] 26 f9 [2] 3a d6 }

  condition:
    any of them
}