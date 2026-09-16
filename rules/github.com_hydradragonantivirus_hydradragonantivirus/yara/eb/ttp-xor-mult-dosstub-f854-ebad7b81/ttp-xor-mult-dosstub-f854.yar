rule TTP_XOR_MULT_DOSStub_f854 {
  strings:
    $key_f854 = { ac 3c [2] d8 24 [2] 9f 26 [2] d8 37 [2] 96 3b [2] 9a 31 [2] 8d 3a [2] 96 74 [2] ab }

  condition:
    any of them
}