rule TTP_XOR_MULT_DOSStub_f841 {
  strings:
    $key_f841 = { ac 29 [2] d8 31 [2] 9f 33 [2] d8 22 [2] 96 2e [2] 9a 24 [2] 8d 2f [2] 96 61 [2] ab }

  condition:
    any of them
}