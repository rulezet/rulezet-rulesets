rule TTP_XOR_QUAD_CurrentVersionRun_881a {
  strings:
    $key_881a = { db 75 [2] ff 7b [2] d4 57 [2] fa 75 [2] ee 6e [2] e1 74 [2] ff 69 [2] fd 68 [2] e6 6e [2] fa 69 [2] e6 46 }

  condition:
    any of them
}