rule TTP_XOR_MULT_DOSStub_f82b {
  strings:
    $key_f82b = { ac 43 [2] d8 5b [2] 9f 59 [2] d8 48 [2] 96 44 [2] 9a 4e [2] 8d 45 [2] 96 0b [2] ab }

  condition:
    any of them
}