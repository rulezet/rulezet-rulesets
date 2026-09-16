rule TTP_XOR_QUAD_CurrentVersionRun_883b {
  strings:
    $key_883b = { db 54 [2] ff 5a [2] d4 76 [2] fa 54 [2] ee 4f [2] e1 55 [2] ff 48 [2] fd 49 [2] e6 4f [2] fa 48 [2] e6 67 }

  condition:
    any of them
}