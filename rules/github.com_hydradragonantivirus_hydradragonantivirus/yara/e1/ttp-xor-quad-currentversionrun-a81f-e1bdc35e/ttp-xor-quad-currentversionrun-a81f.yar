rule TTP_XOR_QUAD_CurrentVersionRun_a81f {
  strings:
    $key_a81f = { fb 70 [2] df 7e [2] f4 52 [2] da 70 [2] ce 6b [2] c1 71 [2] df 6c [2] dd 6d [2] c6 6b [2] da 6c [2] c6 43 }

  condition:
    any of them
}