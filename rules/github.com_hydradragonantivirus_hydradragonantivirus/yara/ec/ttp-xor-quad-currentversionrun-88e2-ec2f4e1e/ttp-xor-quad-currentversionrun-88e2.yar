rule TTP_XOR_QUAD_CurrentVersionRun_88e2 {
  strings:
    $key_88e2 = { db 8d [2] ff 83 [2] d4 af [2] fa 8d [2] ee 96 [2] e1 8c [2] ff 91 [2] fd 90 [2] e6 96 [2] fa 91 [2] e6 be }

  condition:
    any of them
}