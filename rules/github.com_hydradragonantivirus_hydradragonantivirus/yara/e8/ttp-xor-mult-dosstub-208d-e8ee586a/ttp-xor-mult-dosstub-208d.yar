rule TTP_XOR_MULT_DOSStub_208d {
  strings:
    $key_208d = { 74 e5 [2] 00 fd [2] 47 ff [2] 00 ee [2] 4e e2 [2] 42 e8 [2] 55 e3 [2] 4e ad [2] 73 }

  condition:
    any of them
}