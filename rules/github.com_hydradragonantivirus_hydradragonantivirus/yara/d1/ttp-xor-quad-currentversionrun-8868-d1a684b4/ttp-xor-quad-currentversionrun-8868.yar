rule TTP_XOR_QUAD_CurrentVersionRun_8868 {
  strings:
    $key_8868 = { db 07 [2] ff 09 [2] d4 25 [2] fa 07 [2] ee 1c [2] e1 06 [2] ff 1b [2] fd 1a [2] e6 1c [2] fa 1b [2] e6 34 }

  condition:
    any of them
}