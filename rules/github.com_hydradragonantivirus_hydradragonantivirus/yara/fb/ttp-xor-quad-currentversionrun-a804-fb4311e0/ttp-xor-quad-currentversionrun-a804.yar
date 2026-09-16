rule TTP_XOR_QUAD_CurrentVersionRun_a804 {
  strings:
    $key_a804 = { fb 6b [2] df 65 [2] f4 49 [2] da 6b [2] ce 70 [2] c1 6a [2] df 77 [2] dd 76 [2] c6 70 [2] da 77 [2] c6 58 }

  condition:
    any of them
}