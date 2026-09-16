rule TTP_XOR_QUAD_CurrentVersionRun_a845 {
  strings:
    $key_a845 = { fb 2a [2] df 24 [2] f4 08 [2] da 2a [2] ce 31 [2] c1 2b [2] df 36 [2] dd 37 [2] c6 31 [2] da 36 [2] c6 19 }

  condition:
    any of them
}