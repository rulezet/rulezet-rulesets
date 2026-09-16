rule TTP_XOR_QUAD_CurrentVersionRun_afcc {
  strings:
    $key_afcc = { fc a3 [2] d8 ad [2] f3 81 [2] dd a3 [2] c9 b8 [2] c6 a2 [2] d8 bf [2] da be [2] c1 b8 [2] dd bf [2] c1 90 }

  condition:
    any of them
}