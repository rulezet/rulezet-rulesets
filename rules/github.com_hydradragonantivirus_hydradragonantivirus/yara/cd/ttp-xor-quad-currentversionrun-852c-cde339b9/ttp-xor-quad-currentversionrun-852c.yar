rule TTP_XOR_QUAD_CurrentVersionRun_852c {
  strings:
    $key_852c = { d6 43 [2] f2 4d [2] d9 61 [2] f7 43 [2] e3 58 [2] ec 42 [2] f2 5f [2] f0 5e [2] eb 58 [2] f7 5f [2] eb 70 }

  condition:
    any of them
}