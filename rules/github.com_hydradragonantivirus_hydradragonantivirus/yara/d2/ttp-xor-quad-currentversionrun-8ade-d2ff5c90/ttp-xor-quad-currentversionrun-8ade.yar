rule TTP_XOR_QUAD_CurrentVersionRun_8ade {
  strings:
    $key_8ade = { d9 b1 [2] fd bf [2] d6 93 [2] f8 b1 [2] ec aa [2] e3 b0 [2] fd ad [2] ff ac [2] e4 aa [2] f8 ad [2] e4 82 }

  condition:
    any of them
}