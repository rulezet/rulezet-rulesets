rule TTP_XOR_QUAD_CurrentVersionRun_aac1 {
  strings:
    $key_aac1 = { f9 ae [2] dd a0 [2] f6 8c [2] d8 ae [2] cc b5 [2] c3 af [2] dd b2 [2] df b3 [2] c4 b5 [2] d8 b2 [2] c4 9d }

  condition:
    any of them
}