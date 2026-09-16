rule TTP_XOR_QUAD_CurrentVersionRun_a805 {
  strings:
    $key_a805 = { fb 6a [2] df 64 [2] f4 48 [2] da 6a [2] ce 71 [2] c1 6b [2] df 76 [2] dd 77 [2] c6 71 [2] da 76 [2] c6 59 }

  condition:
    any of them
}