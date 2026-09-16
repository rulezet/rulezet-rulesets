rule TTP_XOR_QUAD_CurrentVersionRun_833b {
  strings:
    $key_833b = { d0 54 [2] f4 5a [2] df 76 [2] f1 54 [2] e5 4f [2] ea 55 [2] f4 48 [2] f6 49 [2] ed 4f [2] f1 48 [2] ed 67 }

  condition:
    any of them
}