rule TTP_XOR_QUAD_CurrentVersionRun_88c5 {
  strings:
    $key_88c5 = { db aa [2] ff a4 [2] d4 88 [2] fa aa [2] ee b1 [2] e1 ab [2] ff b6 [2] fd b7 [2] e6 b1 [2] fa b6 [2] e6 99 }

  condition:
    any of them
}