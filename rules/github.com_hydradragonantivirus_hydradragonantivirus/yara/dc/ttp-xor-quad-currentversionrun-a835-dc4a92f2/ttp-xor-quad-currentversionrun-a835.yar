rule TTP_XOR_QUAD_CurrentVersionRun_a835 {
  strings:
    $key_a835 = { fb 5a [2] df 54 [2] f4 78 [2] da 5a [2] ce 41 [2] c1 5b [2] df 46 [2] dd 47 [2] c6 41 [2] da 46 [2] c6 69 }

  condition:
    any of them
}