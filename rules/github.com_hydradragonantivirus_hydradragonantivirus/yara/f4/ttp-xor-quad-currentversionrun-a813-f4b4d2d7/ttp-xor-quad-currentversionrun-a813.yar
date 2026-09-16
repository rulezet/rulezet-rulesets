rule TTP_XOR_QUAD_CurrentVersionRun_a813 {
  strings:
    $key_a813 = { fb 7c [2] df 72 [2] f4 5e [2] da 7c [2] ce 67 [2] c1 7d [2] df 60 [2] dd 61 [2] c6 67 [2] da 60 [2] c6 4f }

  condition:
    any of them
}