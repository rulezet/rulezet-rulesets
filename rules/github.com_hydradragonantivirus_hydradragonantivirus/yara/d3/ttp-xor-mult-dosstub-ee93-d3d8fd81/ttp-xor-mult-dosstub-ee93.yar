rule TTP_XOR_MULT_DOSStub_ee93 {
  strings:
    $key_ee93 = { ba fb [2] ce e3 [2] 89 e1 [2] ce f0 [2] 80 fc [2] 8c f6 [2] 9b fd [2] 80 b3 [2] bd }

  condition:
    any of them
}