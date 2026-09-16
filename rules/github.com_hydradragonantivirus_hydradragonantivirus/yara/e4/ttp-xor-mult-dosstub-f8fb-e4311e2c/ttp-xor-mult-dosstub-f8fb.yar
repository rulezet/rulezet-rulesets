rule TTP_XOR_MULT_DOSStub_f8fb {
  strings:
    $key_f8fb = { ac 93 [2] d8 8b [2] 9f 89 [2] d8 98 [2] 96 94 [2] 9a 9e [2] 8d 95 [2] 96 db [2] ab }

  condition:
    any of them
}