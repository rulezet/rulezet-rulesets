rule TTP_XOR_QUAD_CurrentVersionRun_0d90 {
  strings:
    $key_0d90 = { 5e ff [2] 7a f1 [2] 51 dd [2] 7f ff [2] 6b e4 [2] 64 fe [2] 7a e3 [2] 78 e2 [2] 63 e4 [2] 7f e3 [2] 63 cc }

  condition:
    any of them
}