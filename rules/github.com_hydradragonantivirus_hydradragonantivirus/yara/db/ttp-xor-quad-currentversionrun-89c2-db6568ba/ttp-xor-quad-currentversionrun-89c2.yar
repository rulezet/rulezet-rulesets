rule TTP_XOR_QUAD_CurrentVersionRun_89c2 {
  strings:
    $key_89c2 = { da ad [2] fe a3 [2] d5 8f [2] fb ad [2] ef b6 [2] e0 ac [2] fe b1 [2] fc b0 [2] e7 b6 [2] fb b1 [2] e7 9e }

  condition:
    any of them
}