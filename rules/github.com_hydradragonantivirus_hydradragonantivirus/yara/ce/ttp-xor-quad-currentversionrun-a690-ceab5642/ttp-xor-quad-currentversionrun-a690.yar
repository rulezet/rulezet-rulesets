rule TTP_XOR_QUAD_CurrentVersionRun_a690 {
  strings:
    $key_a690 = { f5 ff [2] d1 f1 [2] fa dd [2] d4 ff [2] c0 e4 [2] cf fe [2] d1 e3 [2] d3 e2 [2] c8 e4 [2] d4 e3 [2] c8 cc }

  condition:
    any of them
}