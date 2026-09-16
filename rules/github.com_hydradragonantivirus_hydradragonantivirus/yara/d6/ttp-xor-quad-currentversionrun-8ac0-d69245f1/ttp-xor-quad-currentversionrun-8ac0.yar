rule TTP_XOR_QUAD_CurrentVersionRun_8ac0 {
  strings:
    $key_8ac0 = { d9 af [2] fd a1 [2] d6 8d [2] f8 af [2] ec b4 [2] e3 ae [2] fd b3 [2] ff b2 [2] e4 b4 [2] f8 b3 [2] e4 9c }

  condition:
    any of them
}