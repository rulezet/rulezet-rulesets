rule TTP_XOR_QUAD_CurrentVersionRun_84e3 {
  strings:
    $key_84e3 = { d7 8c [2] f3 82 [2] d8 ae [2] f6 8c [2] e2 97 [2] ed 8d [2] f3 90 [2] f1 91 [2] ea 97 [2] f6 90 [2] ea bf }

  condition:
    any of them
}