rule TTP_XOR_QUAD_CurrentVersionRun_bd90 {
  strings:
    $key_bd90 = { ee ff [2] ca f1 [2] e1 dd [2] cf ff [2] db e4 [2] d4 fe [2] ca e3 [2] c8 e2 [2] d3 e4 [2] cf e3 [2] d3 cc }

  condition:
    any of them
}