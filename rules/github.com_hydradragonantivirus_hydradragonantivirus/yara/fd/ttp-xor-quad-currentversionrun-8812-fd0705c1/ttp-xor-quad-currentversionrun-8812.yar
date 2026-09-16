rule TTP_XOR_QUAD_CurrentVersionRun_8812 {
  strings:
    $key_8812 = { db 7d [2] ff 73 [2] d4 5f [2] fa 7d [2] ee 66 [2] e1 7c [2] ff 61 [2] fd 60 [2] e6 66 [2] fa 61 [2] e6 4e }

  condition:
    any of them
}