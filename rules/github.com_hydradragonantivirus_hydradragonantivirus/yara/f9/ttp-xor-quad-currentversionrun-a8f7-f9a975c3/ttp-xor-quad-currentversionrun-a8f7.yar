rule TTP_XOR_QUAD_CurrentVersionRun_a8f7 {
  strings:
    $key_a8f7 = { fb 98 [2] df 96 [2] f4 ba [2] da 98 [2] ce 83 [2] c1 99 [2] df 84 [2] dd 85 [2] c6 83 [2] da 84 [2] c6 ab }

  condition:
    any of them
}