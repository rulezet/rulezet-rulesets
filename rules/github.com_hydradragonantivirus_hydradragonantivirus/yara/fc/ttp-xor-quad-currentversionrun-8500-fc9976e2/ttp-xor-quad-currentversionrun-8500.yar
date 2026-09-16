rule TTP_XOR_QUAD_CurrentVersionRun_8500 {
  strings:
    $key_8500 = { d6 6f [2] f2 61 [2] d9 4d [2] f7 6f [2] e3 74 [2] ec 6e [2] f2 73 [2] f0 72 [2] eb 74 [2] f7 73 [2] eb 5c }

  condition:
    any of them
}