rule TTP_XOR_MULT_DOSStub_77fd {
  strings:
    $key_77fd = { 23 95 [2] 57 8d [2] 10 8f [2] 57 9e [2] 19 92 [2] 15 98 [2] 02 93 [2] 19 dd [2] 24 }

  condition:
    any of them
}