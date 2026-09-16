rule TTP_XOR_QUAD_CurrentVersionRun_7a8c {
  strings:
    $key_7a8c = { 29 e3 [2] 0d ed [2] 26 c1 [2] 08 e3 [2] 1c f8 [2] 13 e2 [2] 0d ff [2] 0f fe [2] 14 f8 [2] 08 ff [2] 14 d0 }

  condition:
    any of them
}