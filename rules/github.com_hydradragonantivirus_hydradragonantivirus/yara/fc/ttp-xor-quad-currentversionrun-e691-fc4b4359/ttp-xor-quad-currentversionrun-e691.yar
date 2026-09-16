rule TTP_XOR_QUAD_CurrentVersionRun_e691 {
  strings:
    $key_e691 = { b5 fe [2] 91 f0 [2] ba dc [2] 94 fe [2] 80 e5 [2] 8f ff [2] 91 e2 [2] 93 e3 [2] 88 e5 [2] 94 e2 [2] 88 cd }

  condition:
    any of them
}