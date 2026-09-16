rule TTP_XOR_QUAD_CurrentVersionRun_bbd9 {
  strings:
    $key_bbd9 = { e8 b6 [2] cc b8 [2] e7 94 [2] c9 b6 [2] dd ad [2] d2 b7 [2] cc aa [2] ce ab [2] d5 ad [2] c9 aa [2] d5 85 }

  condition:
    any of them
}