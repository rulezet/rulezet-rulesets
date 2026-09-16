rule TTP_XOR_MULT_DOSStub_f822 {
  strings:
    $key_f822 = { ac 4a [2] d8 52 [2] 9f 50 [2] d8 41 [2] 96 4d [2] 9a 47 [2] 8d 4c [2] 96 02 [2] ab }

  condition:
    any of them
}