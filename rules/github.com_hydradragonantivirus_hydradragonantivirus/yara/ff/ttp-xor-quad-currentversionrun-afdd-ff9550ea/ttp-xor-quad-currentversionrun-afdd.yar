rule TTP_XOR_QUAD_CurrentVersionRun_afdd {
  strings:
    $key_afdd = { fc b2 [2] d8 bc [2] f3 90 [2] dd b2 [2] c9 a9 [2] c6 b3 [2] d8 ae [2] da af [2] c1 a9 [2] dd ae [2] c1 81 }

  condition:
    any of them
}