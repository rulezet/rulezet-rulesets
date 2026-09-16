rule TTP_XOR_QUAD_CurrentVersionRun_8412 {
  strings:
    $key_8412 = { d7 7d [2] f3 73 [2] d8 5f [2] f6 7d [2] e2 66 [2] ed 7c [2] f3 61 [2] f1 60 [2] ea 66 [2] f6 61 [2] ea 4e }

  condition:
    any of them
}