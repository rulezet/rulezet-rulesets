rule TTP_XOR_QUAD_CurrentVersionRun_84fc {
  strings:
    $key_84fc = { d7 93 [2] f3 9d [2] d8 b1 [2] f6 93 [2] e2 88 [2] ed 92 [2] f3 8f [2] f1 8e [2] ea 88 [2] f6 8f [2] ea a0 }

  condition:
    any of them
}