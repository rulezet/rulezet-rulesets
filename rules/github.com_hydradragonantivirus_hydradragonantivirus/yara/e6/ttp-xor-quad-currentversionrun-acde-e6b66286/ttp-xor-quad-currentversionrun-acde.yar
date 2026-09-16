rule TTP_XOR_QUAD_CurrentVersionRun_acde {
  strings:
    $key_acde = { ff b1 [2] db bf [2] f0 93 [2] de b1 [2] ca aa [2] c5 b0 [2] db ad [2] d9 ac [2] c2 aa [2] de ad [2] c2 82 }

  condition:
    any of them
}