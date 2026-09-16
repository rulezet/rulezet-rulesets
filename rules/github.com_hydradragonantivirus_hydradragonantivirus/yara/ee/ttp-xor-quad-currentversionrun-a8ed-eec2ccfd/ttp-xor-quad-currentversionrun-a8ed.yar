rule TTP_XOR_QUAD_CurrentVersionRun_a8ed {
  strings:
    $key_a8ed = { fb 82 [2] df 8c [2] f4 a0 [2] da 82 [2] ce 99 [2] c1 83 [2] df 9e [2] dd 9f [2] c6 99 [2] da 9e [2] c6 b1 }

  condition:
    any of them
}