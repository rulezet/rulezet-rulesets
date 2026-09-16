rule TTP_XOR_QUAD_CurrentVersionRun_a85d {
  strings:
    $key_a85d = { fb 32 [2] df 3c [2] f4 10 [2] da 32 [2] ce 29 [2] c1 33 [2] df 2e [2] dd 2f [2] c6 29 [2] da 2e [2] c6 01 }

  condition:
    any of them
}