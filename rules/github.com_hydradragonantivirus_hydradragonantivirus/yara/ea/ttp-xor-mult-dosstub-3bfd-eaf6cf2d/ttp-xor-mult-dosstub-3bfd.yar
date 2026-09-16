rule TTP_XOR_MULT_DOSStub_3bfd {
  strings:
    $key_3bfd = { 6f 95 [2] 1b 8d [2] 5c 8f [2] 1b 9e [2] 55 92 [2] 59 98 [2] 4e 93 [2] 55 dd [2] 68 }

  condition:
    any of them
}