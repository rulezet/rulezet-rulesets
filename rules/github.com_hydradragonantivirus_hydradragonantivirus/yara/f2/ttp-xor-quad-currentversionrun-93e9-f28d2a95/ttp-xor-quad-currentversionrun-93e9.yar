rule TTP_XOR_QUAD_CurrentVersionRun_93e9 {
  strings:
    $key_93e9 = { c0 86 [2] e4 88 [2] cf a4 [2] e1 86 [2] f5 9d [2] fa 87 [2] e4 9a [2] e6 9b [2] fd 9d [2] e1 9a [2] fd b5 }

  condition:
    any of them
}