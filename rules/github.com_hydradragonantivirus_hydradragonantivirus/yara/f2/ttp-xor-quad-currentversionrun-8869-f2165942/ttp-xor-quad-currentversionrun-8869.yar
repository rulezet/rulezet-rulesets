rule TTP_XOR_QUAD_CurrentVersionRun_8869 {
  strings:
    $key_8869 = { db 06 [2] ff 08 [2] d4 24 [2] fa 06 [2] ee 1d [2] e1 07 [2] ff 1a [2] fd 1b [2] e6 1d [2] fa 1a [2] e6 35 }

  condition:
    any of them
}