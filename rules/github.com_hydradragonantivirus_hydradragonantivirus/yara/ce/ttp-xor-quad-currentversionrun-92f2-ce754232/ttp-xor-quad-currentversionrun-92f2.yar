rule TTP_XOR_QUAD_CurrentVersionRun_92f2 {
  strings:
    $key_92f2 = { c1 9d [2] e5 93 [2] ce bf [2] e0 9d [2] f4 86 [2] fb 9c [2] e5 81 [2] e7 80 [2] fc 86 [2] e0 81 [2] fc ae }

  condition:
    any of them
}