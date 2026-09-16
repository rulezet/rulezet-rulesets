rule TTP_XOR_QUAD_CurrentVersionRun_afb6 {
  strings:
    $key_afb6 = { fc d9 [2] d8 d7 [2] f3 fb [2] dd d9 [2] c9 c2 [2] c6 d8 [2] d8 c5 [2] da c4 [2] c1 c2 [2] dd c5 [2] c1 ea }

  condition:
    any of them
}