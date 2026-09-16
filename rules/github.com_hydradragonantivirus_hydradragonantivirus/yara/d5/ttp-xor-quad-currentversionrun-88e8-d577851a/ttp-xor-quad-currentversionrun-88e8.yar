rule TTP_XOR_QUAD_CurrentVersionRun_88e8 {
  strings:
    $key_88e8 = { db 87 [2] ff 89 [2] d4 a5 [2] fa 87 [2] ee 9c [2] e1 86 [2] ff 9b [2] fd 9a [2] e6 9c [2] fa 9b [2] e6 b4 }

  condition:
    any of them
}