rule TTP_XOR_QUAD_CurrentVersionRun_ea8c {
  strings:
    $key_ea8c = { b9 e3 [2] 9d ed [2] b6 c1 [2] 98 e3 [2] 8c f8 [2] 83 e2 [2] 9d ff [2] 9f fe [2] 84 f8 [2] 98 ff [2] 84 d0 }

  condition:
    any of them
}