rule TTP_XOR_QUAD_CurrentVersionRun_8451 {
  strings:
    $key_8451 = { d7 3e [2] f3 30 [2] d8 1c [2] f6 3e [2] e2 25 [2] ed 3f [2] f3 22 [2] f1 23 [2] ea 25 [2] f6 22 [2] ea 0d }

  condition:
    any of them
}