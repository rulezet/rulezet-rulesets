rule TTP_XOR_QUAD_CurrentVersionRun_88e9 {
  strings:
    $key_88e9 = { db 86 [2] ff 88 [2] d4 a4 [2] fa 86 [2] ee 9d [2] e1 87 [2] ff 9a [2] fd 9b [2] e6 9d [2] fa 9a [2] e6 b5 }

  condition:
    any of them
}