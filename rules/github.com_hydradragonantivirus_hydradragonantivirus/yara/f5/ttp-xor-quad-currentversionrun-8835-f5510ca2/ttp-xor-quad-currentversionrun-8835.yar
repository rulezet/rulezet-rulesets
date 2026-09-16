rule TTP_XOR_QUAD_CurrentVersionRun_8835 {
  strings:
    $key_8835 = { db 5a [2] ff 54 [2] d4 78 [2] fa 5a [2] ee 41 [2] e1 5b [2] ff 46 [2] fd 47 [2] e6 41 [2] fa 46 [2] e6 69 }

  condition:
    any of them
}