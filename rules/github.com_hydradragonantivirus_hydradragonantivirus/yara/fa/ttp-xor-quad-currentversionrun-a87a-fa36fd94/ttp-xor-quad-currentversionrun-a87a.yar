rule TTP_XOR_QUAD_CurrentVersionRun_a87a {
  strings:
    $key_a87a = { fb 15 [2] df 1b [2] f4 37 [2] da 15 [2] ce 0e [2] c1 14 [2] df 09 [2] dd 08 [2] c6 0e [2] da 09 [2] c6 26 }

  condition:
    any of them
}