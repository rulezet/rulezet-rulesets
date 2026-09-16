rule TTP_XOR_MULT_DOSStub_f83b {
  strings:
    $key_f83b = { ac 53 [2] d8 4b [2] 9f 49 [2] d8 58 [2] 96 54 [2] 9a 5e [2] 8d 55 [2] 96 1b [2] ab }

  condition:
    any of them
}