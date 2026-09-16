rule TTP_XOR_QUAD_CurrentVersionRun_aedd {
  strings:
    $key_aedd = { fd b2 [2] d9 bc [2] f2 90 [2] dc b2 [2] c8 a9 [2] c7 b3 [2] d9 ae [2] db af [2] c0 a9 [2] dc ae [2] c0 81 }

  condition:
    any of them
}