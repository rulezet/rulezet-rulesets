rule TTP_XOR_MULT_DOSStub_f85d {
  strings:
    $key_f85d = { ac 35 [2] d8 2d [2] 9f 2f [2] d8 3e [2] 96 32 [2] 9a 38 [2] 8d 33 [2] 96 7d [2] ab }

  condition:
    any of them
}