rule TTP_XOR_MULT_DOSStub_1bfd {
  strings:
    $key_1bfd = { 4f 95 [2] 3b 8d [2] 7c 8f [2] 3b 9e [2] 75 92 [2] 79 98 [2] 6e 93 [2] 75 dd [2] 48 }

  condition:
    any of them
}