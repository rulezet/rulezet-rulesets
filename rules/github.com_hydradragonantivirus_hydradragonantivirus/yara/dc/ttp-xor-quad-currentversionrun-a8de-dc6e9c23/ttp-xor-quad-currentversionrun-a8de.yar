rule TTP_XOR_QUAD_CurrentVersionRun_a8de {
  strings:
    $key_a8de = { fb b1 [2] df bf [2] f4 93 [2] da b1 [2] ce aa [2] c1 b0 [2] df ad [2] dd ac [2] c6 aa [2] da ad [2] c6 82 }

  condition:
    any of them
}