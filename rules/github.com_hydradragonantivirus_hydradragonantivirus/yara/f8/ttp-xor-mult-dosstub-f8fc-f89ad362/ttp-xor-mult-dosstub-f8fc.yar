rule TTP_XOR_MULT_DOSStub_f8fc {
  strings:
    $key_f8fc = { ac 94 [2] d8 8c [2] 9f 8e [2] d8 9f [2] 96 93 [2] 9a 99 [2] 8d 92 [2] 96 dc [2] ab }

  condition:
    any of them
}