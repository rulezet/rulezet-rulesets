rule TTP_XOR_MULT_DOSStub_f872 {
  strings:
    $key_f872 = { ac 1a [2] d8 02 [2] 9f 00 [2] d8 11 [2] 96 1d [2] 9a 17 [2] 8d 1c [2] 96 52 [2] ab }

  condition:
    any of them
}