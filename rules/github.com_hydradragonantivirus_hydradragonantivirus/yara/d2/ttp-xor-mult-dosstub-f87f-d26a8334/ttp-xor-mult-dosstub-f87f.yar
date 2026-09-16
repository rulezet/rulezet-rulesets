rule TTP_XOR_MULT_DOSStub_f87f {
  strings:
    $key_f87f = { ac 17 [2] d8 0f [2] 9f 0d [2] d8 1c [2] 96 10 [2] 9a 1a [2] 8d 11 [2] 96 5f [2] ab }

  condition:
    any of them
}