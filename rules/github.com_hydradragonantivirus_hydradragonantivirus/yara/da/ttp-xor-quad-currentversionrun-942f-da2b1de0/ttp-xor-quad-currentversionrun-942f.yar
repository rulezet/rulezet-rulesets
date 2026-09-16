rule TTP_XOR_QUAD_CurrentVersionRun_942f {
  strings:
    $key_942f = { c7 40 [2] e3 4e [2] c8 62 [2] e6 40 [2] f2 5b [2] fd 41 [2] e3 5c [2] e1 5d [2] fa 5b [2] e6 5c [2] fa 73 }

  condition:
    any of them
}