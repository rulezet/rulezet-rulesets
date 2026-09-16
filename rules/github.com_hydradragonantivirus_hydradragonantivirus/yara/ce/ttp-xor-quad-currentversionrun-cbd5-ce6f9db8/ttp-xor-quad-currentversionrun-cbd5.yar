rule TTP_XOR_QUAD_CurrentVersionRun_cbd5 {
  strings:
    $key_cbd5 = { 98 ba [2] bc b4 [2] 97 98 [2] b9 ba [2] ad a1 [2] a2 bb [2] bc a6 [2] be a7 [2] a5 a1 [2] b9 a6 [2] a5 89 }

  condition:
    any of them
}