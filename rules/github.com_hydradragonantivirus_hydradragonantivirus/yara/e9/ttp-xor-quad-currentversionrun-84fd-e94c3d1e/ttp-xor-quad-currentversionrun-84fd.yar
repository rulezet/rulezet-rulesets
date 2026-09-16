rule TTP_XOR_QUAD_CurrentVersionRun_84fd {
  strings:
    $key_84fd = { d7 92 [2] f3 9c [2] d8 b0 [2] f6 92 [2] e2 89 [2] ed 93 [2] f3 8e [2] f1 8f [2] ea 89 [2] f6 8e [2] ea a1 }

  condition:
    any of them
}