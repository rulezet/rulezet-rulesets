rule TTP_XOR_MULT_DOSStub_f81b {
  strings:
    $key_f81b = { ac 73 [2] d8 6b [2] 9f 69 [2] d8 78 [2] 96 74 [2] 9a 7e [2] 8d 75 [2] 96 3b [2] ab }

  condition:
    any of them
}