rule TTP_XOR_MULT_DOSStub_44fd {
  strings:
    $key_44fd = { 10 95 [2] 64 8d [2] 23 8f [2] 64 9e [2] 2a 92 [2] 26 98 [2] 31 93 [2] 2a dd [2] 17 }

  condition:
    any of them
}