rule TTP_XOR_QUAD_CurrentVersionRun_884b {
  strings:
    $key_884b = { db 24 [2] ff 2a [2] d4 06 [2] fa 24 [2] ee 3f [2] e1 25 [2] ff 38 [2] fd 39 [2] e6 3f [2] fa 38 [2] e6 17 }

  condition:
    any of them
}