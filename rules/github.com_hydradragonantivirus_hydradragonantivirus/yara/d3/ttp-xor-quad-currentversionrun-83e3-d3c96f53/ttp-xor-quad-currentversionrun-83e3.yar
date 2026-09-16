rule TTP_XOR_QUAD_CurrentVersionRun_83e3 {
  strings:
    $key_83e3 = { d0 8c [2] f4 82 [2] df ae [2] f1 8c [2] e5 97 [2] ea 8d [2] f4 90 [2] f6 91 [2] ed 97 [2] f1 90 [2] ed bf }

  condition:
    any of them
}