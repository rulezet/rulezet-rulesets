rule TTP_XOR_QUAD_CurrentVersionRun_16b0 {
  strings:
    $key_16b0 = { 45 df [2] 61 d1 [2] 4a fd [2] 64 df [2] 70 c4 [2] 7f de [2] 61 c3 [2] 63 c2 [2] 78 c4 [2] 64 c3 [2] 78 ec }

  condition:
    any of them
}