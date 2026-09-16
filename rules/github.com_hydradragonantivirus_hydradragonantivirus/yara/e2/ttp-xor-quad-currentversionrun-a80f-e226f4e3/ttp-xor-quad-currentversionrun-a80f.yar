rule TTP_XOR_QUAD_CurrentVersionRun_a80f {
  strings:
    $key_a80f = { fb 60 [2] df 6e [2] f4 42 [2] da 60 [2] ce 7b [2] c1 61 [2] df 7c [2] dd 7d [2] c6 7b [2] da 7c [2] c6 53 }

  condition:
    any of them
}