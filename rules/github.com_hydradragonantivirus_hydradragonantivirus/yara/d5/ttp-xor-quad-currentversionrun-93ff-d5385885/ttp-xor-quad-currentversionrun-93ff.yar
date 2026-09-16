rule TTP_XOR_QUAD_CurrentVersionRun_93ff {
  strings:
    $key_93ff = { c0 90 [2] e4 9e [2] cf b2 [2] e1 90 [2] f5 8b [2] fa 91 [2] e4 8c [2] e6 8d [2] fd 8b [2] e1 8c [2] fd a3 }

  condition:
    any of them
}