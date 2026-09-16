rule TTP_XOR_QUAD_CurrentVersionRun_a8f4 {
  strings:
    $key_a8f4 = { fb 9b [2] df 95 [2] f4 b9 [2] da 9b [2] ce 80 [2] c1 9a [2] df 87 [2] dd 86 [2] c6 80 [2] da 87 [2] c6 a8 }

  condition:
    any of them
}