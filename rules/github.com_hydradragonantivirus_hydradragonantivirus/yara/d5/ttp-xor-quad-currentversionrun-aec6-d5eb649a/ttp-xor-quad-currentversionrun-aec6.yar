rule TTP_XOR_QUAD_CurrentVersionRun_aec6 {
  strings:
    $key_aec6 = { fd a9 [2] d9 a7 [2] f2 8b [2] dc a9 [2] c8 b2 [2] c7 a8 [2] d9 b5 [2] db b4 [2] c0 b2 [2] dc b5 [2] c0 9a }

  condition:
    any of them
}