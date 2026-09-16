rule TTP_XOR_QUAD_CurrentVersionRun_8800 {
  strings:
    $key_8800 = { db 6f [2] ff 61 [2] d4 4d [2] fa 6f [2] ee 74 [2] e1 6e [2] ff 73 [2] fd 72 [2] e6 74 [2] fa 73 [2] e6 5c }

  condition:
    any of them
}