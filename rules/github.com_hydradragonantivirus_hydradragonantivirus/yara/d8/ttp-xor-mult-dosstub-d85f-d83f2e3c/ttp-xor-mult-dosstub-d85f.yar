rule TTP_XOR_MULT_DOSStub_d85f {
  strings:
    $key_d85f = { 8c 37 [2] f8 2f [2] bf 2d [2] f8 3c [2] b6 30 [2] ba 3a [2] ad 31 [2] b6 7f [2] 8b }

  condition:
    any of them
}