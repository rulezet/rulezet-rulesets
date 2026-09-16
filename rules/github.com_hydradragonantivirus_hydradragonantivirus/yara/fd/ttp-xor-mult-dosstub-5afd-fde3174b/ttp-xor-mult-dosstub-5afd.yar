rule TTP_XOR_MULT_DOSStub_5afd {
  strings:
    $key_5afd = { 0e 95 [2] 7a 8d [2] 3d 8f [2] 7a 9e [2] 34 92 [2] 38 98 [2] 2f 93 [2] 34 dd [2] 09 }

  condition:
    any of them
}