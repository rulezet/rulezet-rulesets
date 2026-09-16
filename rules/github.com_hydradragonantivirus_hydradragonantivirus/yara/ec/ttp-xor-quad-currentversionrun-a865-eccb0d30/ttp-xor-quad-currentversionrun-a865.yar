rule TTP_XOR_QUAD_CurrentVersionRun_a865 {
  strings:
    $key_a865 = { fb 0a [2] df 04 [2] f4 28 [2] da 0a [2] ce 11 [2] c1 0b [2] df 16 [2] dd 17 [2] c6 11 [2] da 16 [2] c6 39 }

  condition:
    any of them
}