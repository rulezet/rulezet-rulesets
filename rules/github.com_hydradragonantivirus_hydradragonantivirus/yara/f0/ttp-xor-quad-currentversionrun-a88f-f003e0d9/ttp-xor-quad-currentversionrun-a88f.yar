rule TTP_XOR_QUAD_CurrentVersionRun_a88f {
  strings:
    $key_a88f = { fb e0 [2] df ee [2] f4 c2 [2] da e0 [2] ce fb [2] c1 e1 [2] df fc [2] dd fd [2] c6 fb [2] da fc [2] c6 d3 }

  condition:
    any of them
}