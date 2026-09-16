rule TTP_XOR_QUAD_CurrentVersionRun_88ca {
  strings:
    $key_88ca = { db a5 [2] ff ab [2] d4 87 [2] fa a5 [2] ee be [2] e1 a4 [2] ff b9 [2] fd b8 [2] e6 be [2] fa b9 [2] e6 96 }

  condition:
    any of them
}