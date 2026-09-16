rule TTP_XOR_QUAD_CurrentVersionRun_3c90 {
  strings:
    $key_3c90 = { 6f ff [2] 4b f1 [2] 60 dd [2] 4e ff [2] 5a e4 [2] 55 fe [2] 4b e3 [2] 49 e2 [2] 52 e4 [2] 4e e3 [2] 52 cc }

  condition:
    any of them
}