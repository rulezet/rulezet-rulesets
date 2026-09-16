rule TTP_XOR_QUAD_CurrentVersionRun_a8b2 {
  strings:
    $key_a8b2 = { fb dd [2] df d3 [2] f4 ff [2] da dd [2] ce c6 [2] c1 dc [2] df c1 [2] dd c0 [2] c6 c6 [2] da c1 [2] c6 ee }

  condition:
    any of them
}