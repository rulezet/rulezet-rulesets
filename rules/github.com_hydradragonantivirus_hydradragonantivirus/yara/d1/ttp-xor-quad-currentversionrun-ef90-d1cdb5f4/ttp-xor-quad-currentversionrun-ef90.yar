rule TTP_XOR_QUAD_CurrentVersionRun_ef90 {
  strings:
    $key_ef90 = { bc ff [2] 98 f1 [2] b3 dd [2] 9d ff [2] 89 e4 [2] 86 fe [2] 98 e3 [2] 9a e2 [2] 81 e4 [2] 9d e3 [2] 81 cc }

  condition:
    any of them
}