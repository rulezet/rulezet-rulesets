rule TTP_XOR_QUAD_CurrentVersionRun_a190 {
  strings:
    $key_a190 = { f2 ff [2] d6 f1 [2] fd dd [2] d3 ff [2] c7 e4 [2] c8 fe [2] d6 e3 [2] d4 e2 [2] cf e4 [2] d3 e3 [2] cf cc }

  condition:
    any of them
}