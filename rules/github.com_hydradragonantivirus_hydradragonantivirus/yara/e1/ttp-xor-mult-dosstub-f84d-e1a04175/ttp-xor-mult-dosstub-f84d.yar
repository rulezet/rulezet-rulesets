rule TTP_XOR_MULT_DOSStub_f84d {
  strings:
    $key_f84d = { ac 25 [2] d8 3d [2] 9f 3f [2] d8 2e [2] 96 22 [2] 9a 28 [2] 8d 23 [2] 96 6d [2] ab }

  condition:
    any of them
}