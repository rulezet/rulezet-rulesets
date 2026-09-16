rule TTP_XOR_QUAD_CurrentVersionRun_887d {
  strings:
    $key_887d = { db 12 [2] ff 1c [2] d4 30 [2] fa 12 [2] ee 09 [2] e1 13 [2] ff 0e [2] fd 0f [2] e6 09 [2] fa 0e [2] e6 21 }

  condition:
    any of them
}