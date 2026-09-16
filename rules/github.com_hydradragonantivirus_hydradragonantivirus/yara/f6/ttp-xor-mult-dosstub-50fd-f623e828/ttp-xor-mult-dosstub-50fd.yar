rule TTP_XOR_MULT_DOSStub_50fd {
  strings:
    $key_50fd = { 04 95 [2] 70 8d [2] 37 8f [2] 70 9e [2] 3e 92 [2] 32 98 [2] 25 93 [2] 3e dd [2] 03 }

  condition:
    any of them
}