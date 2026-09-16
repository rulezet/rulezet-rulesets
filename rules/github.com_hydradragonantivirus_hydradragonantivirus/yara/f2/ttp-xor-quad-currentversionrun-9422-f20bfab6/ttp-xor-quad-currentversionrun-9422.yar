rule TTP_XOR_QUAD_CurrentVersionRun_9422 {
  strings:
    $key_9422 = { c7 4d [2] e3 43 [2] c8 6f [2] e6 4d [2] f2 56 [2] fd 4c [2] e3 51 [2] e1 50 [2] fa 56 [2] e6 51 [2] fa 7e }

  condition:
    any of them
}