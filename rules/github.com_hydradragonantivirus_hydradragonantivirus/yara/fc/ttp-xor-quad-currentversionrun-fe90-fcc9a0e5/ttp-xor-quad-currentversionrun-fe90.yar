rule TTP_XOR_QUAD_CurrentVersionRun_fe90 {
  strings:
    $key_fe90 = { ad ff [2] 89 f1 [2] a2 dd [2] 8c ff [2] 98 e4 [2] 97 fe [2] 89 e3 [2] 8b e2 [2] 90 e4 [2] 8c e3 [2] 90 cc }

  condition:
    any of them
}