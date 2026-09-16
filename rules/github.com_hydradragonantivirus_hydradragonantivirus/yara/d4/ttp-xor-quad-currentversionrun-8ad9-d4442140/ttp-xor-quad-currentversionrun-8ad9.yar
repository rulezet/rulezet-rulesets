rule TTP_XOR_QUAD_CurrentVersionRun_8ad9 {
  strings:
    $key_8ad9 = { d9 b6 [2] fd b8 [2] d6 94 [2] f8 b6 [2] ec ad [2] e3 b7 [2] fd aa [2] ff ab [2] e4 ad [2] f8 aa [2] e4 85 }

  condition:
    any of them
}