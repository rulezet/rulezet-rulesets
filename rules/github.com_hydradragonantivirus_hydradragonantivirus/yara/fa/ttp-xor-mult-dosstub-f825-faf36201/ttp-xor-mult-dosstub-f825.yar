rule TTP_XOR_MULT_DOSStub_f825 {
  strings:
    $key_f825 = { ac 4d [2] d8 55 [2] 9f 57 [2] d8 46 [2] 96 4a [2] 9a 40 [2] 8d 4b [2] 96 05 [2] ab }

  condition:
    any of them
}