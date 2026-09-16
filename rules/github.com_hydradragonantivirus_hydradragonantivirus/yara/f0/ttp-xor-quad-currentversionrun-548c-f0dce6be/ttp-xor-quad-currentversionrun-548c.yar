rule TTP_XOR_QUAD_CurrentVersionRun_548c {
  strings:
    $key_548c = { 07 e3 [2] 23 ed [2] 08 c1 [2] 26 e3 [2] 32 f8 [2] 3d e2 [2] 23 ff [2] 21 fe [2] 3a f8 [2] 26 ff [2] 3a d0 }

  condition:
    any of them
}