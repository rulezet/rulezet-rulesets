rule TTP_XOR_QUAD_CurrentVersionRun_81b1 {
  strings:
    $key_81b1 = { d2 de [2] f6 d0 [2] dd fc [2] f3 de [2] e7 c5 [2] e8 df [2] f6 c2 [2] f4 c3 [2] ef c5 [2] f3 c2 [2] ef ed }

  condition:
    any of them
}