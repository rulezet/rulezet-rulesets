rule TTP_XOR_MULT_DOSStub_f816 {
  strings:
    $key_f816 = { ac 7e [2] d8 66 [2] 9f 64 [2] d8 75 [2] 96 79 [2] 9a 73 [2] 8d 78 [2] 96 36 [2] ab }

  condition:
    any of them
}