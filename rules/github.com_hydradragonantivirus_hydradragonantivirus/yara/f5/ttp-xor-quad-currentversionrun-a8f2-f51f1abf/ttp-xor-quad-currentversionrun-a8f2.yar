rule TTP_XOR_QUAD_CurrentVersionRun_a8f2 {
  strings:
    $key_a8f2 = { fb 9d [2] df 93 [2] f4 bf [2] da 9d [2] ce 86 [2] c1 9c [2] df 81 [2] dd 80 [2] c6 86 [2] da 81 [2] c6 ae }

  condition:
    any of them
}