rule TTP_XOR_QUAD_CurrentVersionRun_a853 {
  strings:
    $key_a853 = { fb 3c [2] df 32 [2] f4 1e [2] da 3c [2] ce 27 [2] c1 3d [2] df 20 [2] dd 21 [2] c6 27 [2] da 20 [2] c6 0f }

  condition:
    any of them
}