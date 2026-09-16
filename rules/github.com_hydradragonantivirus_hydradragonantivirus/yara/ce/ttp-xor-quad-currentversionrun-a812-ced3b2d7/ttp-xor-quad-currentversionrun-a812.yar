rule TTP_XOR_QUAD_CurrentVersionRun_a812 {
  strings:
    $key_a812 = { fb 7d [2] df 73 [2] f4 5f [2] da 7d [2] ce 66 [2] c1 7c [2] df 61 [2] dd 60 [2] c6 66 [2] da 61 [2] c6 4e }

  condition:
    any of them
}