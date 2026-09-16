rule TTP_XOR_QUAD_CurrentVersionRun_a81b {
  strings:
    $key_a81b = { fb 74 [2] df 7a [2] f4 56 [2] da 74 [2] ce 6f [2] c1 75 [2] df 68 [2] dd 69 [2] c6 6f [2] da 68 [2] c6 47 }

  condition:
    any of them
}