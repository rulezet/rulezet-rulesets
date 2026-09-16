rule TTP_XOR_QUAD_CurrentVersionRun_8531 {
  strings:
    $key_8531 = { d6 5e [2] f2 50 [2] d9 7c [2] f7 5e [2] e3 45 [2] ec 5f [2] f2 42 [2] f0 43 [2] eb 45 [2] f7 42 [2] eb 6d }

  condition:
    any of them
}