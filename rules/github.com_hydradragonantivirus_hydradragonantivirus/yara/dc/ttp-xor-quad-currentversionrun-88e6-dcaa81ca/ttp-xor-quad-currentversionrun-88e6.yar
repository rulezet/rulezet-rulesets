rule TTP_XOR_QUAD_CurrentVersionRun_88e6 {
  strings:
    $key_88e6 = { db 89 [2] ff 87 [2] d4 ab [2] fa 89 [2] ee 92 [2] e1 88 [2] ff 95 [2] fd 94 [2] e6 92 [2] fa 95 [2] e6 ba }

  condition:
    any of them
}