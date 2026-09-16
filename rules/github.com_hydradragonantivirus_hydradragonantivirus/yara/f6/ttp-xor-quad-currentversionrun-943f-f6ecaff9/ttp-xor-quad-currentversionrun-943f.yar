rule TTP_XOR_QUAD_CurrentVersionRun_943f {
  strings:
    $key_943f = { c7 50 [2] e3 5e [2] c8 72 [2] e6 50 [2] f2 4b [2] fd 51 [2] e3 4c [2] e1 4d [2] fa 4b [2] e6 4c [2] fa 63 }

  condition:
    any of them
}