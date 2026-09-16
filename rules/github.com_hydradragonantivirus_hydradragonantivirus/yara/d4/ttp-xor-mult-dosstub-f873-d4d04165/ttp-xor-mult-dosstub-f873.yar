rule TTP_XOR_MULT_DOSStub_f873 {
  strings:
    $key_f873 = { ac 1b [2] d8 03 [2] 9f 01 [2] d8 10 [2] 96 1c [2] 9a 16 [2] 8d 1d [2] 96 53 [2] ab }

  condition:
    any of them
}