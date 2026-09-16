rule TTP_XOR_QUAD_CurrentVersionRun_a863 {
  strings:
    $key_a863 = { fb 0c [2] df 02 [2] f4 2e [2] da 0c [2] ce 17 [2] c1 0d [2] df 10 [2] dd 11 [2] c6 17 [2] da 10 [2] c6 3f }

  condition:
    any of them
}