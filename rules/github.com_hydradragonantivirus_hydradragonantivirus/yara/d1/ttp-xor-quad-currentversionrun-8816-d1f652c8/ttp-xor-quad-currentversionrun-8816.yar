rule TTP_XOR_QUAD_CurrentVersionRun_8816 {
  strings:
    $key_8816 = { db 79 [2] ff 77 [2] d4 5b [2] fa 79 [2] ee 62 [2] e1 78 [2] ff 65 [2] fd 64 [2] e6 62 [2] fa 65 [2] e6 4a }

  condition:
    any of them
}