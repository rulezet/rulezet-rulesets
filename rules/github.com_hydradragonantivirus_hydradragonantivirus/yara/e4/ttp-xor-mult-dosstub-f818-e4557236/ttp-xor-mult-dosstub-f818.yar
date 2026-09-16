rule TTP_XOR_MULT_DOSStub_f818 {
  strings:
    $key_f818 = { ac 70 [2] d8 68 [2] 9f 6a [2] d8 7b [2] 96 77 [2] 9a 7d [2] 8d 76 [2] 96 38 [2] ab }

  condition:
    any of them
}