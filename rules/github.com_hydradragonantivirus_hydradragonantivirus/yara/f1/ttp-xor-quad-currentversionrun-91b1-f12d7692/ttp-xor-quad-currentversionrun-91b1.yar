rule TTP_XOR_QUAD_CurrentVersionRun_91b1 {
  strings:
    $key_91b1 = { c2 de [2] e6 d0 [2] cd fc [2] e3 de [2] f7 c5 [2] f8 df [2] e6 c2 [2] e4 c3 [2] ff c5 [2] e3 c2 [2] ff ed }

  condition:
    any of them
}