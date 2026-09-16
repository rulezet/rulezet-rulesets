rule TTP_XOR_MULT_DOSStub_f877 {
  strings:
    $key_f877 = { ac 1f [2] d8 07 [2] 9f 05 [2] d8 14 [2] 96 18 [2] 9a 12 [2] 8d 19 [2] 96 57 [2] ab }

  condition:
    any of them
}