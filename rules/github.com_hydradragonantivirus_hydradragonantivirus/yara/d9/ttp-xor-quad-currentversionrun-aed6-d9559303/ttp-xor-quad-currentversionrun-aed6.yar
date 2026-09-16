rule TTP_XOR_QUAD_CurrentVersionRun_aed6 {
  strings:
    $key_aed6 = { fd b9 [2] d9 b7 [2] f2 9b [2] dc b9 [2] c8 a2 [2] c7 b8 [2] d9 a5 [2] db a4 [2] c0 a2 [2] dc a5 [2] c0 8a }

  condition:
    any of them
}