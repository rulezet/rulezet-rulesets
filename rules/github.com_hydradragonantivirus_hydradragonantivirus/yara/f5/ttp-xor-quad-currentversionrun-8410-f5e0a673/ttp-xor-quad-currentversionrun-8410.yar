rule TTP_XOR_QUAD_CurrentVersionRun_8410 {
  strings:
    $key_8410 = { d7 7f [2] f3 71 [2] d8 5d [2] f6 7f [2] e2 64 [2] ed 7e [2] f3 63 [2] f1 62 [2] ea 64 [2] f6 63 [2] ea 4c }

  condition:
    any of them
}