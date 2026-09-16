rule TTP_XOR_QUAD_CurrentVersionRun_aace {
  strings:
    $key_aace = { f9 a1 [2] dd af [2] f6 83 [2] d8 a1 [2] cc ba [2] c3 a0 [2] dd bd [2] df bc [2] c4 ba [2] d8 bd [2] c4 92 }

  condition:
    any of them
}