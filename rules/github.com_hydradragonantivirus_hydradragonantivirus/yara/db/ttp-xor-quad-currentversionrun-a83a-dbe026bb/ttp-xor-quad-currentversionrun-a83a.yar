rule TTP_XOR_QUAD_CurrentVersionRun_a83a {
  strings:
    $key_a83a = { fb 55 [2] df 5b [2] f4 77 [2] da 55 [2] ce 4e [2] c1 54 [2] df 49 [2] dd 48 [2] c6 4e [2] da 49 [2] c6 66 }

  condition:
    any of them
}