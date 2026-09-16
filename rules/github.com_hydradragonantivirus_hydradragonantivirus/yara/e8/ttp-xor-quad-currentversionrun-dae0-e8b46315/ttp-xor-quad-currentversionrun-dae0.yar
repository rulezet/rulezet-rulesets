rule TTP_XOR_QUAD_CurrentVersionRun_dae0 {
  strings:
    $key_dae0 = { 89 8f [2] ad 81 [2] 86 ad [2] a8 8f [2] bc 94 [2] b3 8e [2] ad 93 [2] af 92 [2] b4 94 [2] a8 93 [2] b4 bc }

  condition:
    any of them
}