rule TTP_XOR_MULT_DOSStub_1dfd {
  strings:
    $key_1dfd = { 49 95 [2] 3d 8d [2] 7a 8f [2] 3d 9e [2] 73 92 [2] 7f 98 [2] 68 93 [2] 73 dd [2] 4e }

  condition:
    any of them
}