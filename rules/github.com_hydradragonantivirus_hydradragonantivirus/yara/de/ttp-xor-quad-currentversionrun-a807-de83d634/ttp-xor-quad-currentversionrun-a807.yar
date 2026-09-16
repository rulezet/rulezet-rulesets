rule TTP_XOR_QUAD_CurrentVersionRun_a807 {
  strings:
    $key_a807 = { fb 68 [2] df 66 [2] f4 4a [2] da 68 [2] ce 73 [2] c1 69 [2] df 74 [2] dd 75 [2] c6 73 [2] da 74 [2] c6 5b }

  condition:
    any of them
}