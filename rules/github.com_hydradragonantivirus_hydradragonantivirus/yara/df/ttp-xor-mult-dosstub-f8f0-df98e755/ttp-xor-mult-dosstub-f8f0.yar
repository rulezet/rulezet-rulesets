rule TTP_XOR_MULT_DOSStub_f8f0 {
  strings:
    $key_f8f0 = { ac 98 [2] d8 80 [2] 9f 82 [2] d8 93 [2] 96 9f [2] 9a 95 [2] 8d 9e [2] 96 d0 [2] ab }

  condition:
    any of them
}