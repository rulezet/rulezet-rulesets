rule TTP_XOR_MULT_DOSStub_da92 {
  strings:
    $key_da92 = { 8e fa [2] fa e2 [2] bd e0 [2] fa f1 [2] b4 fd [2] b8 f7 [2] af fc [2] b4 b2 [2] 89 }

  condition:
    any of them
}