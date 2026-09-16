rule TTP_XOR_QUAD_CurrentVersionRun_d29f {
  strings:
    $key_d29f = { 81 f0 [2] a5 fe [2] 8e d2 [2] a0 f0 [2] b4 eb [2] bb f1 [2] a5 ec [2] a7 ed [2] bc eb [2] a0 ec [2] bc c3 }

  condition:
    any of them
}