rule TTP_XOR_QUAD_CurrentVersionRun_8532 {
  strings:
    $key_8532 = { d6 5d [2] f2 53 [2] d9 7f [2] f7 5d [2] e3 46 [2] ec 5c [2] f2 41 [2] f0 40 [2] eb 46 [2] f7 41 [2] eb 6e }

  condition:
    any of them
}