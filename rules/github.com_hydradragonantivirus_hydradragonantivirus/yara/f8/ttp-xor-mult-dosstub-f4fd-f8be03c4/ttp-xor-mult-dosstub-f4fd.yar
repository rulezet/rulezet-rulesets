rule TTP_XOR_MULT_DOSStub_f4fd {
  strings:
    $key_f4fd = { a0 95 [2] d4 8d [2] 93 8f [2] d4 9e [2] 9a 92 [2] 96 98 [2] 81 93 [2] 9a dd [2] a7 }

  condition:
    any of them
}