rule TTP_XOR_QUAD_CurrentVersionRun_8845 {
  strings:
    $key_8845 = { db 2a [2] ff 24 [2] d4 08 [2] fa 2a [2] ee 31 [2] e1 2b [2] ff 36 [2] fd 37 [2] e6 31 [2] fa 36 [2] e6 19 }

  condition:
    any of them
}