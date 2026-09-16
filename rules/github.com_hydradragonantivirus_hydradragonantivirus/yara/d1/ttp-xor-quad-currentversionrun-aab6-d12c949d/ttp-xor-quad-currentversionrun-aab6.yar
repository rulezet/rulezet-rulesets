rule TTP_XOR_QUAD_CurrentVersionRun_aab6 {
  strings:
    $key_aab6 = { f9 d9 [2] dd d7 [2] f6 fb [2] d8 d9 [2] cc c2 [2] c3 d8 [2] dd c5 [2] df c4 [2] c4 c2 [2] d8 c5 [2] c4 ea }

  condition:
    any of them
}