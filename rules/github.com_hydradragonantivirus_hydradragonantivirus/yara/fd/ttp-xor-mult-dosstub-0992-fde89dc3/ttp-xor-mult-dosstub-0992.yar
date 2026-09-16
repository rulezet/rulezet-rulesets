rule TTP_XOR_MULT_DOSStub_0992 {
  strings:
    $key_0992 = { 5d fa [2] 29 e2 [2] 6e e0 [2] 29 f1 [2] 67 fd [2] 6b f7 [2] 7c fc [2] 67 b2 [2] 5a }

  condition:
    any of them
}