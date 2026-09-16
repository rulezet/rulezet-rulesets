rule TTP_XOR_QUAD_CurrentVersionRun_a850 {
  strings:
    $key_a850 = { fb 3f [2] df 31 [2] f4 1d [2] da 3f [2] ce 24 [2] c1 3e [2] df 23 [2] dd 22 [2] c6 24 [2] da 23 [2] c6 0c }

  condition:
    any of them
}