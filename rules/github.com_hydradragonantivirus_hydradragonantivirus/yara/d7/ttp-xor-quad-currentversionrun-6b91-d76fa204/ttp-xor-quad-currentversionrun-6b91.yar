rule TTP_XOR_QUAD_CurrentVersionRun_6b91 {
  strings:
    $key_6b91 = { 38 fe [2] 1c f0 [2] 37 dc [2] 19 fe [2] 0d e5 [2] 02 ff [2] 1c e2 [2] 1e e3 [2] 05 e5 [2] 19 e2 [2] 05 cd }

  condition:
    any of them
}