rule TTP_XOR_MULT_DOSStub_f88b {
  strings:
    $key_f88b = { ac e3 [2] d8 fb [2] 9f f9 [2] d8 e8 [2] 96 e4 [2] 9a ee [2] 8d e5 [2] 96 ab [2] ab }

  condition:
    any of them
}