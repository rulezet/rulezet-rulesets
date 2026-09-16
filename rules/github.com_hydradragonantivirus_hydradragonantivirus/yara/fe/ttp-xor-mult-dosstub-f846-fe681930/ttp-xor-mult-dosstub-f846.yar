rule TTP_XOR_MULT_DOSStub_f846 {
  strings:
    $key_f846 = { ac 2e [2] d8 36 [2] 9f 34 [2] d8 25 [2] 96 29 [2] 9a 23 [2] 8d 28 [2] 96 66 [2] ab }

  condition:
    any of them
}