rule TTP_XOR_QUAD_CurrentVersionRun_a880 {
  strings:
    $key_a880 = { fb ef [2] df e1 [2] f4 cd [2] da ef [2] ce f4 [2] c1 ee [2] df f3 [2] dd f2 [2] c6 f4 [2] da f3 [2] c6 dc }

  condition:
    any of them
}