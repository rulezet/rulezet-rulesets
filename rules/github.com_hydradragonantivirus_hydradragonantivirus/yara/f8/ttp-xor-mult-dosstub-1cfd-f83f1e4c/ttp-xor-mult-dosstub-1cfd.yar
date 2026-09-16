rule TTP_XOR_MULT_DOSStub_1cfd {
  strings:
    $key_1cfd = { 48 95 [2] 3c 8d [2] 7b 8f [2] 3c 9e [2] 72 92 [2] 7e 98 [2] 69 93 [2] 72 dd [2] 4f }

  condition:
    any of them
}