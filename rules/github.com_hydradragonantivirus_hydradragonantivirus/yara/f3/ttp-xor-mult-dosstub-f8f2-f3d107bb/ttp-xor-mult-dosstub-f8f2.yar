rule TTP_XOR_MULT_DOSStub_f8f2 {
  strings:
    $key_f8f2 = { ac 9a [2] d8 82 [2] 9f 80 [2] d8 91 [2] 96 9d [2] 9a 97 [2] 8d 9c [2] 96 d2 [2] ab }

  condition:
    any of them
}