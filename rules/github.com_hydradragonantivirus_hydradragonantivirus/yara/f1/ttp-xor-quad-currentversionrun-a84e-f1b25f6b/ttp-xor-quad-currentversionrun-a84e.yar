rule TTP_XOR_QUAD_CurrentVersionRun_a84e {
  strings:
    $key_a84e = { fb 21 [2] df 2f [2] f4 03 [2] da 21 [2] ce 3a [2] c1 20 [2] df 3d [2] dd 3c [2] c6 3a [2] da 3d [2] c6 12 }

  condition:
    any of them
}