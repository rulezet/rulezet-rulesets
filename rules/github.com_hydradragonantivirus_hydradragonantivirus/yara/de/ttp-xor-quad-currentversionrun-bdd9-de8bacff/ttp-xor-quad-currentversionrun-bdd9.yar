rule TTP_XOR_QUAD_CurrentVersionRun_bdd9 {
  strings:
    $key_bdd9 = { ee b6 [2] ca b8 [2] e1 94 [2] cf b6 [2] db ad [2] d4 b7 [2] ca aa [2] c8 ab [2] d3 ad [2] cf aa [2] d3 85 }

  condition:
    any of them
}