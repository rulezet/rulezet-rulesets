rule TTP_XOR_QUAD_CurrentVersionRun_a819 {
  strings:
    $key_a819 = { fb 76 [2] df 78 [2] f4 54 [2] da 76 [2] ce 6d [2] c1 77 [2] df 6a [2] dd 6b [2] c6 6d [2] da 6a [2] c6 45 }

  condition:
    any of them
}