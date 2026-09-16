rule TTP_XOR_QUAD_CurrentVersionRun_1890 {
  strings:
    $key_1890 = { 4b ff [2] 6f f1 [2] 44 dd [2] 6a ff [2] 7e e4 [2] 71 fe [2] 6f e3 [2] 6d e2 [2] 76 e4 [2] 6a e3 [2] 76 cc }

  condition:
    any of them
}