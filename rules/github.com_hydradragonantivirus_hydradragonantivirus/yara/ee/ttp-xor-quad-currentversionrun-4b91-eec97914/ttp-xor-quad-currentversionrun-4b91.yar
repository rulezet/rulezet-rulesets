rule TTP_XOR_QUAD_CurrentVersionRun_4b91 {
  strings:
    $key_4b91 = { 18 fe [2] 3c f0 [2] 17 dc [2] 39 fe [2] 2d e5 [2] 22 ff [2] 3c e2 [2] 3e e3 [2] 25 e5 [2] 39 e2 [2] 25 cd }

  condition:
    any of them
}