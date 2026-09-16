rule TTP_XOR_QUAD_CurrentVersionRun_88f2 {
  strings:
    $key_88f2 = { db 9d [2] ff 93 [2] d4 bf [2] fa 9d [2] ee 86 [2] e1 9c [2] ff 81 [2] fd 80 [2] e6 86 [2] fa 81 [2] e6 ae }

  condition:
    any of them
}