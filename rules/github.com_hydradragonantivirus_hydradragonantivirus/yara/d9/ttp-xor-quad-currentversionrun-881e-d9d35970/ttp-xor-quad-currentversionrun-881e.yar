rule TTP_XOR_QUAD_CurrentVersionRun_881e {
  strings:
    $key_881e = { db 71 [2] ff 7f [2] d4 53 [2] fa 71 [2] ee 6a [2] e1 70 [2] ff 6d [2] fd 6c [2] e6 6a [2] fa 6d [2] e6 42 }

  condition:
    any of them
}