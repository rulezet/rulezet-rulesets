rule TTP_XOR_QUAD_CurrentVersionRun_a827 {
  strings:
    $key_a827 = { fb 48 [2] df 46 [2] f4 6a [2] da 48 [2] ce 53 [2] c1 49 [2] df 54 [2] dd 55 [2] c6 53 [2] da 54 [2] c6 7b }

  condition:
    any of them
}