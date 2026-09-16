rule TTP_XOR_QUAD_CurrentVersionRun_8328 {
  strings:
    $key_8328 = { d0 47 [2] f4 49 [2] df 65 [2] f1 47 [2] e5 5c [2] ea 46 [2] f4 5b [2] f6 5a [2] ed 5c [2] f1 5b [2] ed 74 }

  condition:
    any of them
}