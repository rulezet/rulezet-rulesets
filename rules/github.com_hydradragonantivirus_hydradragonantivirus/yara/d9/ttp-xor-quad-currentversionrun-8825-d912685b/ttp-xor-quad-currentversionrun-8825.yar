rule TTP_XOR_QUAD_CurrentVersionRun_8825 {
  strings:
    $key_8825 = { db 4a [2] ff 44 [2] d4 68 [2] fa 4a [2] ee 51 [2] e1 4b [2] ff 56 [2] fd 57 [2] e6 51 [2] fa 56 [2] e6 79 }

  condition:
    any of them
}