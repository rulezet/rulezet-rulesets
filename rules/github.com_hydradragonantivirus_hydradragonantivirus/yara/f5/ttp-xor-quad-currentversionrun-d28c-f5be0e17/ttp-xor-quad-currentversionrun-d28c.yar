rule TTP_XOR_QUAD_CurrentVersionRun_d28c {
  strings:
    $key_d28c = { 81 e3 [2] a5 ed [2] 8e c1 [2] a0 e3 [2] b4 f8 [2] bb e2 [2] a5 ff [2] a7 fe [2] bc f8 [2] a0 ff [2] bc d0 }

  condition:
    any of them
}