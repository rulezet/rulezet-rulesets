rule TTP_XOR_MULT_DOSStub_608d {
  strings:
    $key_608d = { 34 e5 [2] 40 fd [2] 07 ff [2] 40 ee [2] 0e e2 [2] 02 e8 [2] 15 e3 [2] 0e ad [2] 33 }

  condition:
    any of them
}