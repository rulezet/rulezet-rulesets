rule TTP_XOR_QUAD_CurrentVersionRun_a8dc {
  strings:
    $key_a8dc = { fb b3 [2] df bd [2] f4 91 [2] da b3 [2] ce a8 [2] c1 b2 [2] df af [2] dd ae [2] c6 a8 [2] da af [2] c6 80 }

  condition:
    any of them
}