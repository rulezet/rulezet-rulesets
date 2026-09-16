rule TTP_XOR_MULT_DOSStub_d8fd {
  strings:
    $key_d8fd = { 8c 95 [2] f8 8d [2] bf 8f [2] f8 9e [2] b6 92 [2] ba 98 [2] ad 93 [2] b6 dd [2] 8b }

  condition:
    any of them
}