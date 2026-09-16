rule TTP_XOR_MULT_DOSStub_f5fd {
  strings:
    $key_f5fd = { a1 95 [2] d5 8d [2] 92 8f [2] d5 9e [2] 9b 92 [2] 97 98 [2] 80 93 [2] 9b dd [2] a6 }

  condition:
    any of them
}