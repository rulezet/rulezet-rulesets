rule TTP_XOR_QUAD_CurrentVersionRun_8521 {
  strings:
    $key_8521 = { d6 4e [2] f2 40 [2] d9 6c [2] f7 4e [2] e3 55 [2] ec 4f [2] f2 52 [2] f0 53 [2] eb 55 [2] f7 52 [2] eb 7d }

  condition:
    any of them
}