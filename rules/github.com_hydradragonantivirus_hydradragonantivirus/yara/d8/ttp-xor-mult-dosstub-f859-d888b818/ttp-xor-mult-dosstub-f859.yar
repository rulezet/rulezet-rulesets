rule TTP_XOR_MULT_DOSStub_f859 {
  strings:
    $key_f859 = { ac 31 [2] d8 29 [2] 9f 2b [2] d8 3a [2] 96 36 [2] 9a 3c [2] 8d 37 [2] 96 79 [2] ab }

  condition:
    any of them
}