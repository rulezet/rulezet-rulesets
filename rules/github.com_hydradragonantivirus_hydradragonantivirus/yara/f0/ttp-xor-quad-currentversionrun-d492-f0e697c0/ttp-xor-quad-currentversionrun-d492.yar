rule TTP_XOR_QUAD_CurrentVersionRun_d492 {
  strings:
    $key_d492 = { 87 fd [2] a3 f3 [2] 88 df [2] a6 fd [2] b2 e6 [2] bd fc [2] a3 e1 [2] a1 e0 [2] ba e6 [2] a6 e1 [2] ba ce }

  condition:
    any of them
}