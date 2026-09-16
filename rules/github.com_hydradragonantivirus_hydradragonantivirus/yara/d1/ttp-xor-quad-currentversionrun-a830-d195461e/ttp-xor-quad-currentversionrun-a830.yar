rule TTP_XOR_QUAD_CurrentVersionRun_a830 {
  strings:
    $key_a830 = { fb 5f [2] df 51 [2] f4 7d [2] da 5f [2] ce 44 [2] c1 5e [2] df 43 [2] dd 42 [2] c6 44 [2] da 43 [2] c6 6c }

  condition:
    any of them
}