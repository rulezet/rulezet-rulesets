rule TTP_XOR_QUAD_CurrentVersionRun_a816 {
  strings:
    $key_a816 = { fb 79 [2] df 77 [2] f4 5b [2] da 79 [2] ce 62 [2] c1 78 [2] df 65 [2] dd 64 [2] c6 62 [2] da 65 [2] c6 4a }

  condition:
    any of them
}