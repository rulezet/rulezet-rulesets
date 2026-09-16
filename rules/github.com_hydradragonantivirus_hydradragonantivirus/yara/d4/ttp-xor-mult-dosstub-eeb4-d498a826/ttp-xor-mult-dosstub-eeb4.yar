rule TTP_XOR_MULT_DOSStub_eeb4 {
  strings:
    $key_eeb4 = { ba dc [2] ce c4 [2] 89 c6 [2] ce d7 [2] 80 db [2] 8c d1 [2] 9b da [2] 80 94 [2] bd }

  condition:
    any of them
}