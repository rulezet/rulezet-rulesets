rule TTP_XOR_QUAD_CurrentVersionRun_6190 {
  strings:
    $key_6190 = { 32 ff [2] 16 f1 [2] 3d dd [2] 13 ff [2] 07 e4 [2] 08 fe [2] 16 e3 [2] 14 e2 [2] 0f e4 [2] 13 e3 [2] 0f cc }

  condition:
    any of them
}