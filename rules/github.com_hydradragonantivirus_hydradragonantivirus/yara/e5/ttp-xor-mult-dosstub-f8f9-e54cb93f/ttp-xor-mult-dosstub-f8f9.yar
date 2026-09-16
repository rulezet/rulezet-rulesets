rule TTP_XOR_MULT_DOSStub_f8f9 {
  strings:
    $key_f8f9 = { ac 91 [2] d8 89 [2] 9f 8b [2] d8 9a [2] 96 96 [2] 9a 9c [2] 8d 97 [2] 96 d9 [2] ab }

  condition:
    any of them
}