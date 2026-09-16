rule TTP_XOR_QUAD_CurrentVersionRun_a860 {
  strings:
    $key_a860 = { fb 0f [2] df 01 [2] f4 2d [2] da 0f [2] ce 14 [2] c1 0e [2] df 13 [2] dd 12 [2] c6 14 [2] da 13 [2] c6 3c }

  condition:
    any of them
}