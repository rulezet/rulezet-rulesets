rule TTP_XOR_QUAD_CurrentVersionRun_8874 {
  strings:
    $key_8874 = { db 1b [2] ff 15 [2] d4 39 [2] fa 1b [2] ee 00 [2] e1 1a [2] ff 07 [2] fd 06 [2] e6 00 [2] fa 07 [2] e6 28 }

  condition:
    any of them
}