rule TTP_XOR_QUAD_CurrentVersionRun_88c0 {
  strings:
    $key_88c0 = { db af [2] ff a1 [2] d4 8d [2] fa af [2] ee b4 [2] e1 ae [2] ff b3 [2] fd b2 [2] e6 b4 [2] fa b3 [2] e6 9c }

  condition:
    any of them
}