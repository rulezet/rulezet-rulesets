rule TTP_XOR_QUAD_CurrentVersionRun_943e {
  strings:
    $key_943e = { c7 51 [2] e3 5f [2] c8 73 [2] e6 51 [2] f2 4a [2] fd 50 [2] e3 4d [2] e1 4c [2] fa 4a [2] e6 4d [2] fa 62 }

  condition:
    any of them
}