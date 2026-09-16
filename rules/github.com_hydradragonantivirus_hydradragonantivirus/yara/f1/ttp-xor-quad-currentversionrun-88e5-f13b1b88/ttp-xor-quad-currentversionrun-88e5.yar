rule TTP_XOR_QUAD_CurrentVersionRun_88e5 {
  strings:
    $key_88e5 = { db 8a [2] ff 84 [2] d4 a8 [2] fa 8a [2] ee 91 [2] e1 8b [2] ff 96 [2] fd 97 [2] e6 91 [2] fa 96 [2] e6 b9 }

  condition:
    any of them
}