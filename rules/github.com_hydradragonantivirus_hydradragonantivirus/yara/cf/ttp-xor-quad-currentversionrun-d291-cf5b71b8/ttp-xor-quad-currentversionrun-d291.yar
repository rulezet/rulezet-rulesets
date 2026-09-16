rule TTP_XOR_QUAD_CurrentVersionRun_d291 {
  strings:
    $key_d291 = { 81 fe [2] a5 f0 [2] 8e dc [2] a0 fe [2] b4 e5 [2] bb ff [2] a5 e2 [2] a7 e3 [2] bc e5 [2] a0 e2 [2] bc cd }

  condition:
    any of them
}