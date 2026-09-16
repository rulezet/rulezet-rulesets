rule TTP_XOR_QUAD_CurrentVersionRun_a821 {
  strings:
    $key_a821 = { fb 4e [2] df 40 [2] f4 6c [2] da 4e [2] ce 55 [2] c1 4f [2] df 52 [2] dd 53 [2] c6 55 [2] da 52 [2] c6 7d }

  condition:
    any of them
}