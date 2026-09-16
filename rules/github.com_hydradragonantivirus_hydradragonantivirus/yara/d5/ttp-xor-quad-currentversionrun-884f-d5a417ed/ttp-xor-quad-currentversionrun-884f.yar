rule TTP_XOR_QUAD_CurrentVersionRun_884f {
  strings:
    $key_884f = { db 20 [2] ff 2e [2] d4 02 [2] fa 20 [2] ee 3b [2] e1 21 [2] ff 3c [2] fd 3d [2] e6 3b [2] fa 3c [2] e6 13 }

  condition:
    any of them
}