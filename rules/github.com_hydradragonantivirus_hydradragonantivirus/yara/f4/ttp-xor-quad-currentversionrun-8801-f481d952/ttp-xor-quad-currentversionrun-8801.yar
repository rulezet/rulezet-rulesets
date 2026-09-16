rule TTP_XOR_QUAD_CurrentVersionRun_8801 {
  strings:
    $key_8801 = { db 6e [2] ff 60 [2] d4 4c [2] fa 6e [2] ee 75 [2] e1 6f [2] ff 72 [2] fd 73 [2] e6 75 [2] fa 72 [2] e6 5d }

  condition:
    any of them
}