rule TTP_XOR_MULT_DOSStub_da93 {
  strings:
    $key_da93 = { 8e fb [2] fa e3 [2] bd e1 [2] fa f0 [2] b4 fc [2] b8 f6 [2] af fd [2] b4 b3 [2] 89 }

  condition:
    any of them
}