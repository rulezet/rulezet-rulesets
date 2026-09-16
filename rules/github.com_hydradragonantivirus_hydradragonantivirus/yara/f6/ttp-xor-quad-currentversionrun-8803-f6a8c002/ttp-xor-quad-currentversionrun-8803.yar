rule TTP_XOR_QUAD_CurrentVersionRun_8803 {
  strings:
    $key_8803 = { db 6c [2] ff 62 [2] d4 4e [2] fa 6c [2] ee 77 [2] e1 6d [2] ff 70 [2] fd 71 [2] e6 77 [2] fa 70 [2] e6 5f }

  condition:
    any of them
}