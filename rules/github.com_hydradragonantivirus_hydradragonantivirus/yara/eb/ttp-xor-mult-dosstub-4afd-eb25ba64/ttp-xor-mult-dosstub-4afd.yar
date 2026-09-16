rule TTP_XOR_MULT_DOSStub_4afd {
  strings:
    $key_4afd = { 1e 95 [2] 6a 8d [2] 2d 8f [2] 6a 9e [2] 24 92 [2] 28 98 [2] 3f 93 [2] 24 dd [2] 19 }

  condition:
    any of them
}