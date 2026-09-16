rule TTP_XOR_MULT_DOSStub_f867 {
  strings:
    $key_f867 = { ac 0f [2] d8 17 [2] 9f 15 [2] d8 04 [2] 96 08 [2] 9a 02 [2] 8d 09 [2] 96 47 [2] ab }

  condition:
    any of them
}