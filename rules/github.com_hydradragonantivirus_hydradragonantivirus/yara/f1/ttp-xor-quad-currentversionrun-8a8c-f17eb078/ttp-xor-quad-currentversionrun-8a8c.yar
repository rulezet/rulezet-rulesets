rule TTP_XOR_QUAD_CurrentVersionRun_8a8c {
  strings:
    $key_8a8c = { d9 e3 [2] fd ed [2] d6 c1 [2] f8 e3 [2] ec f8 [2] e3 e2 [2] fd ff [2] ff fe [2] e4 f8 [2] f8 ff [2] e4 d0 }

  condition:
    any of them
}