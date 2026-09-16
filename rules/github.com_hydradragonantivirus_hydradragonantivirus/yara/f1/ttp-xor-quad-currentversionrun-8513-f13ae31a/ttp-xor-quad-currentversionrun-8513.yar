rule TTP_XOR_QUAD_CurrentVersionRun_8513 {
  strings:
    $key_8513 = { d6 7c [2] f2 72 [2] d9 5e [2] f7 7c [2] e3 67 [2] ec 7d [2] f2 60 [2] f0 61 [2] eb 67 [2] f7 60 [2] eb 4f }

  condition:
    any of them
}