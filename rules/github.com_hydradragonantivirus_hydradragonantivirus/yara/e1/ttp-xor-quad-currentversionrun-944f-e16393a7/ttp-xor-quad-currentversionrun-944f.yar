rule TTP_XOR_QUAD_CurrentVersionRun_944f {
  strings:
    $key_944f = { c7 20 [2] e3 2e [2] c8 02 [2] e6 20 [2] f2 3b [2] fd 21 [2] e3 3c [2] e1 3d [2] fa 3b [2] e6 3c [2] fa 13 }

  condition:
    any of them
}