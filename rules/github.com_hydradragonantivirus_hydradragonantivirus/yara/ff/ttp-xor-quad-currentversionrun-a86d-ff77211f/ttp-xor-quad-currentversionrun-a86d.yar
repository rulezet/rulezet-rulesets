rule TTP_XOR_QUAD_CurrentVersionRun_a86d {
  strings:
    $key_a86d = { fb 02 [2] df 0c [2] f4 20 [2] da 02 [2] ce 19 [2] c1 03 [2] df 1e [2] dd 1f [2] c6 19 [2] da 1e [2] c6 31 }

  condition:
    any of them
}