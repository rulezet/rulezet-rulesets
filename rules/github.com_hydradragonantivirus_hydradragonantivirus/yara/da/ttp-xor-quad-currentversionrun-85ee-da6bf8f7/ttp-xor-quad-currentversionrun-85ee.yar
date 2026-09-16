rule TTP_XOR_QUAD_CurrentVersionRun_85ee {
  strings:
    $key_85ee = { d6 81 [2] f2 8f [2] d9 a3 [2] f7 81 [2] e3 9a [2] ec 80 [2] f2 9d [2] f0 9c [2] eb 9a [2] f7 9d [2] eb b2 }

  condition:
    any of them
}