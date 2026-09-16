rule TTP_XOR_MULT_DOSStub_f8fd {
  strings:
    $key_f8fd = { ac 95 [2] d8 8d [2] 9f 8f [2] d8 9e [2] 96 92 [2] 9a 98 [2] 8d 93 [2] 96 dd [2] ab }

  condition:
    any of them
}