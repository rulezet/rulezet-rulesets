rule TTP_XOR_QUAD_CurrentVersionRun_93ca {
  strings:
    $key_93ca = { c0 a5 [2] e4 ab [2] cf 87 [2] e1 a5 [2] f5 be [2] fa a4 [2] e4 b9 [2] e6 b8 [2] fd be [2] e1 b9 [2] fd 96 }

  condition:
    any of them
}