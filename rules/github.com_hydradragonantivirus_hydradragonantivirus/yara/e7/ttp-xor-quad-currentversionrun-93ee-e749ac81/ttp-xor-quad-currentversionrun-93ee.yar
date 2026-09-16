rule TTP_XOR_QUAD_CurrentVersionRun_93ee {
  strings:
    $key_93ee = { c0 81 [2] e4 8f [2] cf a3 [2] e1 81 [2] f5 9a [2] fa 80 [2] e4 9d [2] e6 9c [2] fd 9a [2] e1 9d [2] fd b2 }

  condition:
    any of them
}