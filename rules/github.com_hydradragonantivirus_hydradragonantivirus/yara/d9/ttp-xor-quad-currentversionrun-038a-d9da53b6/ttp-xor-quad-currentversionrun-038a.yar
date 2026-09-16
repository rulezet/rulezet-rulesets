rule TTP_XOR_QUAD_CurrentVersionRun_038a {
  strings:
    $key_038a = { 50 e5 [2] 74 eb [2] 5f c7 [2] 71 e5 [2] 65 fe [2] 6a e4 [2] 74 f9 [2] 76 f8 [2] 6d fe [2] 71 f9 [2] 6d d6 }

  condition:
    any of them
}