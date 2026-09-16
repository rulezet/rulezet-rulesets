rule TTP_XOR_QUAD_CurrentVersionRun_a8ab {
  strings:
    $key_a8ab = { fb c4 [2] df ca [2] f4 e6 [2] da c4 [2] ce df [2] c1 c5 [2] df d8 [2] dd d9 [2] c6 df [2] da d8 [2] c6 f7 }

  condition:
    any of them
}