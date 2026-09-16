rule TTP_XOR_QUAD_CurrentVersionRun_8844 {
  strings:
    $key_8844 = { db 2b [2] ff 25 [2] d4 09 [2] fa 2b [2] ee 30 [2] e1 2a [2] ff 37 [2] fd 36 [2] e6 30 [2] fa 37 [2] e6 18 }

  condition:
    any of them
}