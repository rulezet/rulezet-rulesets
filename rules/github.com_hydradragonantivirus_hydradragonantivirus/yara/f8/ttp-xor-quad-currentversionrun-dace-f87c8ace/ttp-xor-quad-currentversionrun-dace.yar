rule TTP_XOR_QUAD_CurrentVersionRun_dace {
  strings:
    $key_dace = { 89 a1 [2] ad af [2] 86 83 [2] a8 a1 [2] bc ba [2] b3 a0 [2] ad bd [2] af bc [2] b4 ba [2] a8 bd [2] b4 92 }

  condition:
    any of them
}