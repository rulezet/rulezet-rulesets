rule TTP_XOR_MULT_DOSStub_f8f3 {
  strings:
    $key_f8f3 = { ac 9b [2] d8 83 [2] 9f 81 [2] d8 90 [2] 96 9c [2] 9a 96 [2] 8d 9d [2] 96 d3 [2] ab }

  condition:
    any of them
}