rule TTP_XOR_MULT_DOSStub_f82a {
  strings:
    $key_f82a = { ac 42 [2] d8 5a [2] 9f 58 [2] d8 49 [2] 96 45 [2] 9a 4f [2] 8d 44 [2] 96 0a [2] ab }

  condition:
    any of them
}