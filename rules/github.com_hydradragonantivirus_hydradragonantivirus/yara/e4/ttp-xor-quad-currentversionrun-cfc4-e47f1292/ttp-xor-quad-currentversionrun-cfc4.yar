rule TTP_XOR_QUAD_CurrentVersionRun_cfc4 {
  strings:
    $key_cfc4 = { 9c ab [2] b8 a5 [2] 93 89 [2] bd ab [2] a9 b0 [2] a6 aa [2] b8 b7 [2] ba b6 [2] a1 b0 [2] bd b7 [2] a1 98 }

  condition:
    any of them
}