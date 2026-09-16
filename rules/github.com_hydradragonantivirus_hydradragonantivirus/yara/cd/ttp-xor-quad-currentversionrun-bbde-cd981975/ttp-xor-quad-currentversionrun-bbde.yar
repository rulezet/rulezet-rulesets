rule TTP_XOR_QUAD_CurrentVersionRun_bbde {
  strings:
    $key_bbde = { e8 b1 [2] cc bf [2] e7 93 [2] c9 b1 [2] dd aa [2] d2 b0 [2] cc ad [2] ce ac [2] d5 aa [2] c9 ad [2] d5 82 }

  condition:
    any of them
}