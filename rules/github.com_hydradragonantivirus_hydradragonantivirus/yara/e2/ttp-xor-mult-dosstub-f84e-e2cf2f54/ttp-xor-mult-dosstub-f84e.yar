rule TTP_XOR_MULT_DOSStub_f84e {
  strings:
    $key_f84e = { ac 26 [2] d8 3e [2] 9f 3c [2] d8 2d [2] 96 21 [2] 9a 2b [2] 8d 20 [2] 96 6e [2] ab }

  condition:
    any of them
}