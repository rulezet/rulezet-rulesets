rule TTP_XOR_MULT_DOSStub_f8e2 {
  strings:
    $key_f8e2 = { ac 8a [2] d8 92 [2] 9f 90 [2] d8 81 [2] 96 8d [2] 9a 87 [2] 8d 8c [2] 96 c2 [2] ab }

  condition:
    any of them
}