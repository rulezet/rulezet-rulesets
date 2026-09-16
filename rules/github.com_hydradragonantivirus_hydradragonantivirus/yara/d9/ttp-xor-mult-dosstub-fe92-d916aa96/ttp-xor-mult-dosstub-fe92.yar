rule TTP_XOR_MULT_DOSStub_fe92 {
  strings:
    $key_fe92 = { aa fa [2] de e2 [2] 99 e0 [2] de f1 [2] 90 fd [2] 9c f7 [2] 8b fc [2] 90 b2 [2] ad }

  condition:
    any of them
}