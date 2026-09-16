rule TTP_XOR_QUAD_CurrentVersionRun_8847 {
  strings:
    $key_8847 = { db 28 [2] ff 26 [2] d4 0a [2] fa 28 [2] ee 33 [2] e1 29 [2] ff 34 [2] fd 35 [2] e6 33 [2] fa 34 [2] e6 1b }

  condition:
    any of them
}