rule TTP_XOR_QUAD_CurrentVersionRun_885e {
  strings:
    $key_885e = { db 31 [2] ff 3f [2] d4 13 [2] fa 31 [2] ee 2a [2] e1 30 [2] ff 2d [2] fd 2c [2] e6 2a [2] fa 2d [2] e6 02 }

  condition:
    any of them
}