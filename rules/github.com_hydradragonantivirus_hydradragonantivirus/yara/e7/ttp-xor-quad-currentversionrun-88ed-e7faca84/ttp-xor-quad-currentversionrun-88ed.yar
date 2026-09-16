rule TTP_XOR_QUAD_CurrentVersionRun_88ed {
  strings:
    $key_88ed = { db 82 [2] ff 8c [2] d4 a0 [2] fa 82 [2] ee 99 [2] e1 83 [2] ff 9e [2] fd 9f [2] e6 99 [2] fa 9e [2] e6 b1 }

  condition:
    any of them
}