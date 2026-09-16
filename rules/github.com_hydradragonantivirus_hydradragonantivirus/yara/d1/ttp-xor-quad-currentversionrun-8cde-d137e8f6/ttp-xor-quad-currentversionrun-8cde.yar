rule TTP_XOR_QUAD_CurrentVersionRun_8cde {
  strings:
    $key_8cde = { df b1 [2] fb bf [2] d0 93 [2] fe b1 [2] ea aa [2] e5 b0 [2] fb ad [2] f9 ac [2] e2 aa [2] fe ad [2] e2 82 }

  condition:
    any of them
}