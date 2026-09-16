rule TTP_XOR_QUAD_CurrentVersionRun_887e {
  strings:
    $key_887e = { db 11 [2] ff 1f [2] d4 33 [2] fa 11 [2] ee 0a [2] e1 10 [2] ff 0d [2] fd 0c [2] e6 0a [2] fa 0d [2] e6 22 }

  condition:
    any of them
}