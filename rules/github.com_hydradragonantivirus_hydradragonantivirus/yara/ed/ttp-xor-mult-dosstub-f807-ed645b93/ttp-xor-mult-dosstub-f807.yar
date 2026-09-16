rule TTP_XOR_MULT_DOSStub_f807 {
  strings:
    $key_f807 = { ac 6f [2] d8 77 [2] 9f 75 [2] d8 64 [2] 96 68 [2] 9a 62 [2] 8d 69 [2] 96 27 [2] ab }

  condition:
    any of them
}