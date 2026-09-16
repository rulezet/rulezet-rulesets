rule TTP_XOR_QUAD_CurrentVersionRun_a873 {
  strings:
    $key_a873 = { fb 1c [2] df 12 [2] f4 3e [2] da 1c [2] ce 07 [2] c1 1d [2] df 00 [2] dd 01 [2] c6 07 [2] da 00 [2] c6 2f }

  condition:
    any of them
}