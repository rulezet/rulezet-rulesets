rule TTP_XOR_MULT_DOSStub_cafd {
  strings:
    $key_cafd = { 9e 95 [2] ea 8d [2] ad 8f [2] ea 9e [2] a4 92 [2] a8 98 [2] bf 93 [2] a4 dd [2] 99 }

  condition:
    any of them
}