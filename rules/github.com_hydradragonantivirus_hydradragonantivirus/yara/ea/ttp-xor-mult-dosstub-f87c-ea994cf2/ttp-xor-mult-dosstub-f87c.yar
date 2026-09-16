rule TTP_XOR_MULT_DOSStub_f87c {
  strings:
    $key_f87c = { ac 14 [2] d8 0c [2] 9f 0e [2] d8 1f [2] 96 13 [2] 9a 19 [2] 8d 12 [2] 96 5c [2] ab }

  condition:
    any of them
}