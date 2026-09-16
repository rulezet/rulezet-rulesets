rule TTP_XOR_QUAD_CurrentVersionRun_886e {
  strings:
    $key_886e = { db 01 [2] ff 0f [2] d4 23 [2] fa 01 [2] ee 1a [2] e1 00 [2] ff 1d [2] fd 1c [2] e6 1a [2] fa 1d [2] e6 32 }

  condition:
    any of them
}