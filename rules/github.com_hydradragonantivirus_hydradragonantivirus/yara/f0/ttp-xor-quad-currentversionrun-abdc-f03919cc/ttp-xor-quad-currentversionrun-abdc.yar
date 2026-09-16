rule TTP_XOR_QUAD_CurrentVersionRun_abdc {
  strings:
    $key_abdc = { f8 b3 [2] dc bd [2] f7 91 [2] d9 b3 [2] cd a8 [2] c2 b2 [2] dc af [2] de ae [2] c5 a8 [2] d9 af [2] c5 80 }

  condition:
    any of them
}