rule TTP_XOR_MULT_DOSStub_f87d {
  strings:
    $key_f87d = { ac 15 [2] d8 0d [2] 9f 0f [2] d8 1e [2] 96 12 [2] 9a 18 [2] 8d 13 [2] 96 5d [2] ab }

  condition:
    any of them
}