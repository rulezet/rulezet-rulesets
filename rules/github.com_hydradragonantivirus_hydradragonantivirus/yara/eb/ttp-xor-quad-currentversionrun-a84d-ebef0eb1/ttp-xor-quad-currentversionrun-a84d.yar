rule TTP_XOR_QUAD_CurrentVersionRun_a84d {
  strings:
    $key_a84d = { fb 22 [2] df 2c [2] f4 00 [2] da 22 [2] ce 39 [2] c1 23 [2] df 3e [2] dd 3f [2] c6 39 [2] da 3e [2] c6 11 }

  condition:
    any of them
}