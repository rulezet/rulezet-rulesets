rule TTP_XOR_QUAD_CurrentVersionRun_843f {
  strings:
    $key_843f = { d7 50 [2] f3 5e [2] d8 72 [2] f6 50 [2] e2 4b [2] ed 51 [2] f3 4c [2] f1 4d [2] ea 4b [2] f6 4c [2] ea 63 }

  condition:
    any of them
}