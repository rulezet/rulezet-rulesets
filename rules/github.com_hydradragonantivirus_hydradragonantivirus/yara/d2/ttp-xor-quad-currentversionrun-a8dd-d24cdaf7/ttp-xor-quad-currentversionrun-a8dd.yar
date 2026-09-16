rule TTP_XOR_QUAD_CurrentVersionRun_a8dd {
  strings:
    $key_a8dd = { fb b2 [2] df bc [2] f4 90 [2] da b2 [2] ce a9 [2] c1 b3 [2] df ae [2] dd af [2] c6 a9 [2] da ae [2] c6 81 }

  condition:
    any of them
}