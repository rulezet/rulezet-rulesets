rule TTP_XOR_MULT_DOSStub_f8e1 {
  strings:
    $key_f8e1 = { ac 89 [2] d8 91 [2] 9f 93 [2] d8 82 [2] 96 8e [2] 9a 84 [2] 8d 8f [2] 96 c1 [2] ab }

  condition:
    any of them
}