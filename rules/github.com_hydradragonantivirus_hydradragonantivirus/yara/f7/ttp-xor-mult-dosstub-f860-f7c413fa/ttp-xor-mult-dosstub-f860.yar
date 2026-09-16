rule TTP_XOR_MULT_DOSStub_f860 {
  strings:
    $key_f860 = { ac 08 [2] d8 10 [2] 9f 12 [2] d8 03 [2] 96 0f [2] 9a 05 [2] 8d 0e [2] 96 40 [2] ab }

  condition:
    any of them
}