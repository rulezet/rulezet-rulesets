rule TTP_XOR_QUAD_CurrentVersionRun_aabf {
  strings:
    $key_aabf = { f9 d0 [2] dd de [2] f6 f2 [2] d8 d0 [2] cc cb [2] c3 d1 [2] dd cc [2] df cd [2] c4 cb [2] d8 cc [2] c4 e3 }

  condition:
    any of them
}