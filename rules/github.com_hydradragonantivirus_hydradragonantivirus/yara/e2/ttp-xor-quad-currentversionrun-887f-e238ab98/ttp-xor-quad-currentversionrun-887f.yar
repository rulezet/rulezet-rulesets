rule TTP_XOR_QUAD_CurrentVersionRun_887f {
  strings:
    $key_887f = { db 10 [2] ff 1e [2] d4 32 [2] fa 10 [2] ee 0b [2] e1 11 [2] ff 0c [2] fd 0d [2] e6 0b [2] fa 0c [2] e6 23 }

  condition:
    any of them
}