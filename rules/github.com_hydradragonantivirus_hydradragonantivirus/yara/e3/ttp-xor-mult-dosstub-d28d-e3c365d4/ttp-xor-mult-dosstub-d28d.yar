rule TTP_XOR_MULT_DOSStub_d28d {
  strings:
    $key_d28d = { 86 e5 [2] f2 fd [2] b5 ff [2] f2 ee [2] bc e2 [2] b0 e8 [2] a7 e3 [2] bc ad [2] 81 }

  condition:
    any of them
}