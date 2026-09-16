rule TTP_XOR_QUAD_CurrentVersionRun_648c {
  strings:
    $key_648c = { 37 e3 [2] 13 ed [2] 38 c1 [2] 16 e3 [2] 02 f8 [2] 0d e2 [2] 13 ff [2] 11 fe [2] 0a f8 [2] 16 ff [2] 0a d0 }

  condition:
    any of them
}