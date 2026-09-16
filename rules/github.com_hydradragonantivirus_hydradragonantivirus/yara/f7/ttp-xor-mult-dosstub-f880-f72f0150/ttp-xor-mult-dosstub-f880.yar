rule TTP_XOR_MULT_DOSStub_f880 {
  strings:
    $key_f880 = { ac e8 [2] d8 f0 [2] 9f f2 [2] d8 e3 [2] 96 ef [2] 9a e5 [2] 8d ee [2] 96 a0 [2] ab }

  condition:
    any of them
}