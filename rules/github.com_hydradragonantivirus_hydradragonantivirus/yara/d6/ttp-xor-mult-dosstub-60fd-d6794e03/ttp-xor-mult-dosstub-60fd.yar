rule TTP_XOR_MULT_DOSStub_60fd {
  strings:
    $key_60fd = { 34 95 [2] 40 8d [2] 07 8f [2] 40 9e [2] 0e 92 [2] 02 98 [2] 15 93 [2] 0e dd [2] 33 }

  condition:
    any of them
}