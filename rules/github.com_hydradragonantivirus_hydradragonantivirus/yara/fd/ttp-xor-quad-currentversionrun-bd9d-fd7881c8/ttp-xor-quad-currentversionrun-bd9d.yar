rule TTP_XOR_QUAD_CurrentVersionRun_bd9d {
  strings:
    $key_bd9d = { ee f2 [2] ca fc [2] e1 d0 [2] cf f2 [2] db e9 [2] d4 f3 [2] ca ee [2] c8 ef [2] d3 e9 [2] cf ee [2] d3 c1 }

  condition:
    any of them
}