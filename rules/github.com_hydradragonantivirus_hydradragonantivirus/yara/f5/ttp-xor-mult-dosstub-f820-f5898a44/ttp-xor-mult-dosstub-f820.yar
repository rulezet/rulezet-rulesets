rule TTP_XOR_MULT_DOSStub_f820 {
  strings:
    $key_f820 = { ac 48 [2] d8 50 [2] 9f 52 [2] d8 43 [2] 96 4f [2] 9a 45 [2] 8d 4e [2] 96 00 [2] ab }

  condition:
    any of them
}