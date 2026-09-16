rule TTP_XOR_QUAD_CurrentVersionRun_4890 {
  strings:
    $key_4890 = { 1b ff [2] 3f f1 [2] 14 dd [2] 3a ff [2] 2e e4 [2] 21 fe [2] 3f e3 [2] 3d e2 [2] 26 e4 [2] 3a e3 [2] 26 cc }

  condition:
    any of them
}