rule TTP_XOR_QUAD_CurrentVersionRun_668d {
  strings:
    $key_668d = { 35 e2 [2] 11 ec [2] 3a c0 [2] 14 e2 [2] 00 f9 [2] 0f e3 [2] 11 fe [2] 13 ff [2] 08 f9 [2] 14 fe [2] 08 d1 }

  condition:
    any of them
}