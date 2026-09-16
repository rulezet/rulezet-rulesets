rule TTP_XOR_QUAD_CurrentVersionRun_afaf {
  strings:
    $key_afaf = { fc c0 [2] d8 ce [2] f3 e2 [2] dd c0 [2] c9 db [2] c6 c1 [2] d8 dc [2] da dd [2] c1 db [2] dd dc [2] c1 f3 }

  condition:
    any of them
}