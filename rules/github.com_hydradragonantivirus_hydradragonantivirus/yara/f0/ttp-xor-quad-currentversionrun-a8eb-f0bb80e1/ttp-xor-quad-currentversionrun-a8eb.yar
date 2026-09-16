rule TTP_XOR_QUAD_CurrentVersionRun_a8eb {
  strings:
    $key_a8eb = { fb 84 [2] df 8a [2] f4 a6 [2] da 84 [2] ce 9f [2] c1 85 [2] df 98 [2] dd 99 [2] c6 9f [2] da 98 [2] c6 b7 }

  condition:
    any of them
}